//go:build integration

package auth

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
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
	if w := e.verifyMFA(t, token, totpNow(t, secret)); w.Code != http.StatusOK {
		t.Fatalf("right code: %d %s", w.Code, w.Body.String())
	}
	if w := e.verifyMFA(t, token, totpNow(t, secret)); w.Code != http.StatusUnauthorized {
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

func TestAdminResetOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	admin := e.addUser(t, entities.RoleAdmin)
	adminTokens := e.login(t, admin)
	adminSecret, _ := e.enroll(t, adminTokens.AccessToken)
	target, _, _ := e.enrolledUser(t, entities.RoleUser)

	if w := e.adminReset(t, adminTokens.AccessToken, target.UUID.String(), totpNow(t, adminSecret)); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := e.loginWith(t, target.Email, testPassword); !strings.Contains(w.Body.String(), "access_token") {
		t.Fatalf("%s", w.Body.String())
	}
}
