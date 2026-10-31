//go:build integration

package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/mfa"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
)

func TestMFAFlowOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	u, secret, codes := e.enrolledUser(t, entities.RoleUser)

	token := e.challenge(t, u)
	if e.securedOK(t, token) {
		t.Fatal("an MFA token passed UserAuth")
	}
	if w := e.verifyMFA(t, token, "000000"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: %d %s", w.Code, w.Body.String())
	}
	if w := e.verifyMFA(t, token, e.code(t, secret)); w.Code != http.StatusOK {
		t.Fatalf("right code: %d %s", w.Code, w.Body.String())
	}
	if w := e.verifyMFA(t, token, e.code(t, secret)); w.Code != http.StatusUnauthorized {
		t.Fatalf("spent challenge: %d", w.Code)
	}

	if w := e.verifyMFA(t, e.challenge(t, u), codes[0]); w.Code != http.StatusOK {
		t.Fatalf("backup code: %d %s", w.Code, w.Body.String())
	}
	if w := e.verifyMFA(t, e.challenge(t, u), codes[0]); w.Code != http.StatusUnauthorized {
		t.Fatalf("spent backup code: %d", w.Code)
	}
}

func TestConcurrentGuessesShareOneAttemptCountOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	e.deps.Cfg.AuthSecurity.LockoutThreshold = 0
	e.router = buildRouter(e.deps)
	u, _, _ := e.enrolledUser(t, entities.RoleUser)
	token := e.challenge(t, u)

	const guesses = 20
	invalid := make([]bool, guesses)
	var wg sync.WaitGroup
	for i := 0; i < guesses; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			invalid[i] = strings.Contains(e.verifyMFA(t, token, "000000").Body.String(), "invalid_code")
		}()
	}
	wg.Wait()

	checked := 0
	for _, v := range invalid {
		if v {
			checked++
		}
	}
	if checked > testMFAMaxAttempts {
		t.Fatalf("%d guesses were checked against a limit of %d", checked, testMFAMaxAttempts)
	}
}

// Two requests with one code must yield one success. Two challenges are planted directly,
// because the guard under test is the step's compare-and-set: a single challenge's own
// claim would otherwise decide the race first.
func TestOneTOTPCodeYieldsOneSuccessOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	code := e.code(t, secret)

	const n = 2
	tokens := make([]string, n)
	for i := range tokens {
		raw, err := platformauth.GenerateOpaqueToken()
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = raw
		if err := e.db.Create(&mfa.Challenge{
			UserID: u.ID, TokenHash: platformauth.HashToken(raw), Method: session.MethodPassword,
			ExpiresAt: time.Now().Add(time.Minute),
		}).Error; err != nil {
			t.Fatal(err)
		}
	}

	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range tokens {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if w := e.verifyMFA(t, tokens[i], code); w.Code == http.StatusOK {
				wins.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d successes", wins.Load())
	}
}

func TestReplayIsRefusedOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	code := e.code(t, secret)
	if w := e.verifyMFA(t, e.challenge(t, u), code); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := e.verifyMFA(t, e.challenge(t, u), code); w.Code != http.StatusUnauthorized {
		t.Fatalf("replay: %d %s", w.Code, w.Body.String())
	}
}

func TestParallelBadCodesStayWithinTheThresholdOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	e.deps.Cfg.MFA.MaxAttempts = 100 // the account limit is under test
	e.router = buildRouter(e.deps)
	u, _, _ := e.enrolledUser(t, entities.RoleUser)
	token := e.challenge(t, u)

	const n = 20
	var checked atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if errorCode(t, e.verifyMFA(t, token, "000000")) == "invalid_code" {
				checked.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if checked.Load() != testLockoutThreshold {
		t.Fatalf("%d codes checked, with a threshold of %d", checked.Load(), testLockoutThreshold)
	}
}

func TestParallelSignInsLeaveOneLiveChallengeOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	u, _, _ := e.enrolledUser(t, entities.RoleUser)
	svc := NewService(e.deps)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := svc.Login(context.Background(), LoginRequest{Email: u.Email, Password: testPassword}, LoginContext{}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	var live int64
	if err := e.db.Model(&mfa.Challenge{}).Where("user_id = ? AND consumed_at IS NULL", u.ID).Count(&live).Error; err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("%d live challenges", live)
	}
}

func TestAdminResetOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	admin := e.addUser(t, entities.RoleAdmin)
	adminTokens := e.login(t, admin)
	adminSecret, _ := e.enroll(t, adminTokens.AccessToken)
	target, _, _ := e.enrolledUser(t, entities.RoleUser)

	if w := e.adminReset(t, adminTokens.AccessToken, target.UUID.String(), e.code(t, adminSecret)); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := e.loginWith(t, target.Email, testPassword); !strings.Contains(w.Body.String(), "access_token") {
		t.Fatalf("%s", w.Body.String())
	}
}
