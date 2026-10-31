//go:build integration

package auth

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
)

// The lockout counter is hand-written SQL, so it has to be proven on the real database,
// under the concurrency a guessing attack brings.
func TestLockoutCountsConcurrentFailuresOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	u := e.addUser(t, entities.RoleUser)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.loginWith(t, u.Email, "not-the-password")
		}()
	}
	wg.Wait()

	if w := e.loginWith(t, strings.ToUpper(u.Email), testPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if err := e.db.Exec(`UPDATE login_failures SET window_start = ?`, time.Now().UTC().Add(-2*lockoutWindow)).Error; err != nil {
		t.Fatal(err)
	}
	if w := e.loginWith(t, u.Email, "not-the-password"); w.Code != http.StatusUnauthorized {
		t.Fatalf("a lapsed window starts over: %d", w.Code)
	}
	if w := e.loginWith(t, u.Email, testPassword); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
}

func TestPasswordFlowsOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	u := e.addUser(t, entities.RoleUser)
	a, b := e.login(t, u), e.login(t, u)

	if w := e.changePassword(t, a.AccessToken, testPassword, "password-number-aaaa"); w.Code != http.StatusOK {
		t.Fatalf("change: %d %s", w.Code, w.Body.String())
	}
	if e.securedOK(t, b.AccessToken) || !e.securedOK(t, a.AccessToken) {
		t.Fatal("change password revoked the wrong sessions")
	}

	raw := e.requestResetToken(t, u)
	sent := e.mailer.count()
	if w := e.forgot(t, u.Email); w.Code != http.StatusOK {
		t.Fatalf("forgot: %d", w.Code)
	}
	if e.mailer.count() != sent {
		t.Fatal("the cooldown did not hold back the second email")
	}
	if w := e.reset(t, raw, testPassword); w.Code != http.StatusBadRequest {
		t.Fatalf("reuse from history: %d %s", w.Code, w.Body.String())
	}
	if w := e.reset(t, raw, "password-number-bbbb"); w.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", w.Code, w.Body.String())
	}
	if w := e.reset(t, raw, "password-number-cccc"); w.Code != http.StatusConflict {
		t.Fatalf("second use: %d %s", w.Code, w.Body.String())
	}
	if e.securedOK(t, a.AccessToken) {
		t.Fatal("reset must sign out everywhere")
	}
	if w := e.loginWith(t, u.Email, "password-number-bbbb"); w.Code != http.StatusOK {
		t.Fatalf("login: %d", w.Code)
	}
}
