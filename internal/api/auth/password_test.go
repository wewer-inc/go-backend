package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/passwordhistory"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/passwordreset"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/worker"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

var tokenInLink = regexp.MustCompile(`token=([A-Za-z0-9_-]+)`)

func (e *testEnv) changePassword(t *testing.T, access, current, next string) *httptest.ResponseRecorder {
	t.Helper()
	return e.request(http.MethodPost, "/v1/auth/change-password", access, mustJSON(t, ChangePasswordRequest{CurrentPassword: current, NewPassword: next}))
}

func (e *testEnv) loginWith(t *testing.T, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	return e.request(http.MethodPost, "/v1/auth/login", "", mustJSON(t, LoginRequest{Email: email, Password: password}))
}

func (e *testEnv) forgot(t *testing.T, email string) *httptest.ResponseRecorder {
	t.Helper()
	return e.request(http.MethodPost, "/v1/auth/forgot-password", "", mustJSON(t, ForgotPasswordRequest{Email: email}))
}

func (e *testEnv) reset(t *testing.T, token, next string) *httptest.ResponseRecorder {
	t.Helper()
	return e.request(http.MethodPost, "/v1/auth/reset-password", "", mustJSON(t, ResetPasswordRequest{Token: token, NewPassword: next}))
}

// requestResetToken asks for a link and returns the raw token from the email.
func (e *testEnv) requestResetToken(t *testing.T, u *user.User) string {
	t.Helper()
	if w := e.forgot(t, u.Email); w.Code != http.StatusOK {
		t.Fatalf("forgot: %d", w.Code)
	}
	m := e.mailer.last(t)
	if m.to != u.Email {
		t.Fatalf("mail went to %q", m.to)
	}
	match := tokenInLink.FindStringSubmatch(m.body)
	if match == nil {
		t.Fatalf("no token in %q", m.body)
	}
	return match[1]
}

func TestRegisterAppliesThePasswordPolicy(t *testing.T) {
	e := newEnv(t)
	w := e.request(http.MethodPost, "/v1/auth/register", "", mustJSON(t, RegisterRequest{Name: "N", Email: "n@example.com", Password: "too-short"}))
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "weak_password" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), platformauth.PasswordTooShort) {
		t.Fatalf("details missing: %s", w.Body.String())
	}
	// Longer than bcrypt accepts: the policy refuses it before it can become a 500.
	long := strings.Repeat("日", 25)
	if w := e.request(http.MethodPost, "/v1/auth/register", "", mustJSON(t, RegisterRequest{Name: "N", Email: "n@example.com", Password: long})); w.Code != http.StatusBadRequest {
		t.Fatalf("multibyte over the limit: %d", w.Code)
	}
}

func TestChangePassword(t *testing.T) {
	const next = "a-brand-new-password"
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	here, there := e.login(t, u), e.login(t, u)

	if w := e.changePassword(t, here.AccessToken, testPassword, next); w.Code != http.StatusOK {
		t.Fatalf("change: %d %s", w.Code, w.Body.String())
	}
	if !e.securedOK(t, here.AccessToken) {
		t.Fatal("the current session must survive")
	}
	if e.securedOK(t, there.AccessToken) {
		t.Fatal("other sessions must be revoked")
	}
	if w := e.refresh(t, there.RefreshToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("a revoked session must not refresh: %d", w.Code)
	}
	if w := e.loginWith(t, u.Email, testPassword); w.Code != http.StatusUnauthorized {
		t.Fatalf("old password still works: %d", w.Code)
	}
	if w := e.loginWith(t, u.Email, next); w.Code != http.StatusOK {
		t.Fatalf("new password refused: %d", w.Code)
	}
	if n := e.countEvents(t, audit.EventPasswordChanged); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
	if m := e.mailer.last(t); m.to != u.Email || m.subject != "Your password was changed" {
		t.Fatalf("notification: %+v", m)
	}
	for _, row := range e.auditEvents(t) {
		if strings.Contains(row.Detail, next) || strings.Contains(row.Detail, testPassword) {
			t.Fatalf("a password reached the audit trail: %s", row.Detail)
		}
	}
}

func TestChangePasswordRefusals(t *testing.T) {
	cases := []struct {
		name, current, next, code string
	}{
		{"wrong current password", "not-the-password", "a-brand-new-password", "current_password_incorrect"},
		{"weak new password", testPassword, "short", "weak_password"},
		{"unchanged password", testPassword, testPassword, "password_reused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			u := e.addUser(t, entities.RoleUser)
			tokens := e.login(t, u)
			w := e.changePassword(t, tokens.AccessToken, tc.current, tc.next)
			if w.Code != http.StatusBadRequest || errorCode(t, w) != tc.code {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if !e.securedOK(t, tokens.AccessToken) {
				t.Fatal("a refused change must not sign anyone out")
			}
			if w := e.loginWith(t, u.Email, testPassword); w.Code != http.StatusOK {
				t.Fatalf("the password must not have changed: %d", w.Code)
			}
		})
	}
}

func TestChangePasswordForAGoogleOnlyAccount(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	tokens := e.login(t, u)
	if err := e.db.Model(u).Update("password_hash", "").Error; err != nil {
		t.Fatal(err)
	}
	if w := e.changePassword(t, tokens.AccessToken, "anything-at-all", "a-brand-new-password"); w.Code != http.StatusBadRequest || errorCode(t, w) != "oauth_only" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestPasswordHistoryRefusesRecentAndAllowsOlder(t *testing.T) {
	e := newEnv(t) // the test config keeps 2 previous passwords
	u := e.addUser(t, entities.RoleUser)
	tokens := e.login(t, u)

	step := func(current, next string, want int) {
		t.Helper()
		if w := e.changePassword(t, tokens.AccessToken, current, next); w.Code != want {
			t.Fatalf("%s -> %s: %d %s", current, next, w.Code, w.Body.String())
		}
	}
	const a, b, c = "password-number-aaaa", "password-number-bbbb", "password-number-cccc"
	step(testPassword, a, http.StatusOK)
	step(a, testPassword, http.StatusBadRequest) // history: 1 back
	step(a, b, http.StatusOK)
	step(b, testPassword, http.StatusBadRequest) // history: 2 back
	step(b, c, http.StatusOK)
	step(c, testPassword, http.StatusOK) // 3 back: fell out of the window

	var kept int64
	if err := e.db.Model(&passwordhistory.Entry{}).Where("user_id = ?", u.ID).Count(&kept).Error; err != nil {
		t.Fatal(err)
	}
	if kept != 2 {
		t.Fatalf("history holds %d entries, want it trimmed to 2", kept)
	}
}

func TestForgotPasswordIsIndistinguishable(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)

	known := e.forgot(t, u.Email)
	unknown := e.forgot(t, "nobody@example.com")
	if known.Code != http.StatusOK || unknown.Code != http.StatusOK || known.Body.String() != unknown.Body.String() {
		t.Fatalf("known %d %s, unknown %d %s", known.Code, known.Body, unknown.Code, unknown.Body)
	}
	if n := e.mailer.count(); n != 1 {
		t.Fatalf("%d emails; only the known address gets one", n)
	}
}

type blockingMailer struct {
	release chan struct{}
	started chan struct{}
}

func (m *blockingMailer) Send(ctx context.Context, _, _, _ string) error {
	close(m.started)
	select {
	case <-m.release:
	case <-ctx.Done():
	}
	return nil
}

// The response must not wait for the lookup or the mail, or its timing gives the account
// away. The mailer is held shut until after the handler has answered.
func TestForgotPasswordDoesNotWaitForTheEmail(t *testing.T) {
	mailer := &blockingMailer{release: make(chan struct{}), started: make(chan struct{})}
	w := worker.New(1, 4, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w.Start(ctx)
	e := newEnv(t, func(d *Deps) { d.Mailer = mailer; d.Jobs = w })
	u := e.addUser(t, entities.RoleUser)

	if resp := e.forgot(t, u.Email); resp.Code != http.StatusOK {
		t.Fatalf("status %d", resp.Code)
	}
	select {
	case <-mailer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the job never reached the mailer")
	}
	close(mailer.release)
	stop, cancelStop := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelStop()
	if err := w.Stop(stop); err != nil {
		t.Fatal(err)
	}
}

type refusingQueue struct{}

func (refusingQueue) Enqueue(worker.Job) error { return worker.ErrQueueFull }

func TestForgotPasswordAnswersTheSameWhenTheQueueIsFull(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	normal := e.forgot(t, u.Email)

	full := newEnv(t, func(d *Deps) { d.Jobs = refusingQueue{} })
	v := full.addUser(t, entities.RoleUser)
	dropped := full.forgot(t, v.Email)
	if dropped.Code != normal.Code || dropped.Body.String() != normal.Body.String() {
		t.Fatalf("queue full: %d %s", dropped.Code, dropped.Body)
	}
	if full.mailer.count() != 0 {
		t.Fatal("nothing should have been sent")
	}
}

func TestForgotPasswordRefusesAMalformedAddressPlainly(t *testing.T) {
	e := newEnv(t)
	if w := e.forgot(t, "not-an-email"); w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}

func TestForgotPasswordSendsNothingForAGoogleOnlyAccount(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	if err := e.db.Model(u).Update("password_hash", "").Error; err != nil {
		t.Fatal(err)
	}
	if w := e.forgot(t, u.Email); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if e.mailer.count() != 0 {
		t.Fatal("no email expected")
	}
}

func TestForgotPasswordTouchesNothingOnTheAccount(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	tokens := e.login(t, u)
	e.requestResetToken(t, u)
	if !e.securedOK(t, tokens.AccessToken) {
		t.Fatal("a reset request nobody made must not sign the user out")
	}
	if w := e.loginWith(t, u.Email, testPassword); w.Code != http.StatusOK {
		t.Fatalf("a reset request must not change the password: %d", w.Code)
	}
}

func TestResetTokenIsStoredOnlyAsAHash(t *testing.T) {
	e := newEnv(t)
	raw := e.requestResetToken(t, e.addUser(t, entities.RoleUser))
	var tok passwordreset.Token
	if err := e.db.First(&tok).Error; err != nil {
		t.Fatal(err)
	}
	if tok.TokenHash == raw || tok.TokenHash != platformauth.HashToken(raw) {
		t.Fatal("stored value must be the token's hash")
	}
	for _, row := range e.auditEvents(t) {
		if strings.Contains(row.Detail, raw) {
			t.Fatal("the token reached the audit trail")
		}
	}
}

func TestResetCooldownLimitsEmailsToOneAccount(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Cfg.AuthSecurity.PasswordResetCooldown = time.Hour })
	u := e.addUser(t, entities.RoleUser)
	first := e.forgot(t, u.Email)
	second := e.forgot(t, u.Email)
	if first.Body.String() != second.Body.String() {
		t.Fatal("the cooldown must not change the answer")
	}
	if n := e.mailer.count(); n != 1 {
		t.Fatalf("%d emails", n)
	}
}

func TestNewResetLinkRetiresTheOldOne(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	old := e.requestResetToken(t, u)
	current := e.requestResetToken(t, u)
	if w := e.reset(t, old, "a-brand-new-password"); w.Code != http.StatusConflict {
		t.Fatalf("old link: %d", w.Code)
	}
	if w := e.reset(t, current, "a-brand-new-password"); w.Code != http.StatusOK {
		t.Fatalf("new link: %d %s", w.Code, w.Body.String())
	}
}

func TestResetPassword(t *testing.T) {
	const next = "a-brand-new-password"
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	a, b := e.login(t, u), e.login(t, u)
	raw := e.requestResetToken(t, u)

	w := e.reset(t, raw, next)
	if w.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "access_token") {
		t.Fatal("a reset must not start a session")
	}
	for _, s := range []TokenPairResponse{a, b} {
		if e.securedOK(t, s.AccessToken) {
			t.Fatal("a reset must sign the user out everywhere")
		}
	}
	if resp := e.loginWith(t, u.Email, testPassword); resp.Code != http.StatusUnauthorized {
		t.Fatalf("old password: %d", resp.Code)
	}
	if resp := e.loginWith(t, u.Email, next); resp.Code != http.StatusOK {
		t.Fatalf("new password: %d", resp.Code)
	}
	if n := e.countEvents(t, audit.EventPasswordReset); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
}

func TestResetTokenIsSingleUse(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	raw := e.requestResetToken(t, u)
	if w := e.reset(t, raw, "a-brand-new-password"); w.Code != http.StatusOK {
		t.Fatalf("first use: %d", w.Code)
	}
	w := e.reset(t, raw, "another-new-password")
	if w.Code != http.StatusConflict || errorCode(t, w) != "token_used" {
		t.Fatalf("second use: %d %s", w.Code, w.Body.String())
	}
	if resp := e.loginWith(t, u.Email, "another-new-password"); resp.Code != http.StatusUnauthorized {
		t.Fatal("the second redemption changed the password")
	}
}

func TestConcurrentRedemptionsHaveOneWinner(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	raw := e.requestResetToken(t, u)
	const n = 6
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = e.reset(t, raw, "a-brand-new-password").Code
		}()
	}
	wg.Wait()
	wins := 0
	for _, c := range codes {
		if c == http.StatusOK {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("%d winners in %v", wins, codes)
	}
}

func TestResetTokenExpires(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	raw := e.requestResetToken(t, u)
	if err := e.db.Model(&passwordreset.Token{}).Where("user_id = ?", u.ID).
		Update("expires_at", time.Now().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	w := e.reset(t, raw, "a-brand-new-password")
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "token_expired" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if resp := e.loginWith(t, u.Email, testPassword); resp.Code != http.StatusOK {
		t.Fatal("an expired token changed the password")
	}
}

func TestResetRefusesAnUnknownToken(t *testing.T) {
	e := newEnv(t)
	if w := e.reset(t, "not-a-token", "a-brand-new-password"); w.Code != http.StatusBadRequest || errorCode(t, w) != "invalid_token" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestWeakPasswordLeavesTheResetTokenUsable(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	raw := e.requestResetToken(t, u)
	if w := e.reset(t, raw, "short"); w.Code != http.StatusBadRequest || errorCode(t, w) != "weak_password" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := e.reset(t, raw, testPassword); w.Code != http.StatusBadRequest || errorCode(t, w) != "password_reused" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := e.reset(t, raw, "a-brand-new-password"); w.Code != http.StatusOK {
		t.Fatalf("the token should have survived: %d", w.Code)
	}
}

func TestResetRollsBackIfTheAuditRowCannotBeWritten(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	raw := e.requestResetToken(t, u)
	if err := e.db.Migrator().DropTable(&audit.Log{}); err != nil {
		t.Fatal(err)
	}
	if w := e.reset(t, raw, "a-brand-new-password"); w.Code != http.StatusInternalServerError {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var after user.User
	if err := e.db.First(&after, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(after.PasswordHash), []byte(testPassword)) != nil {
		t.Fatal("the password changed with no audit record")
	}
	var tok passwordreset.Token
	if err := e.db.Where("user_id = ?", u.ID).First(&tok).Error; err != nil {
		t.Fatal(err)
	}
	if tok.ConsumedAt != nil {
		t.Fatal("the token was spent on a change that rolled back")
	}
}

func TestLoginLockout(t *testing.T) {
	e := newEnv(t) // the test config locks after 3 failures
	u := e.addUser(t, entities.RoleUser)
	for i := 0; i < 3; i++ {
		if w := e.loginWith(t, u.Email, "not-the-password"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	w := e.loginWith(t, u.Email, testPassword)
	if w.Code != http.StatusTooManyRequests || errorCode(t, w) != "account_locked" {
		t.Fatalf("the right password while locked: %d %s", w.Code, w.Body.String())
	}
	if n := e.countEvents(t, audit.EventLoginLocked); n != 1 {
		t.Fatalf("%d locked events", n)
	}
	if w := e.loginWith(t, strings.ToUpper(u.Email), testPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("a change of case must not dodge the lock: %d", w.Code)
	}

	// The window lapsing lifts it.
	if err := e.db.Exec(`UPDATE login_failures SET window_start = ?`, time.Now().UTC().Add(-2*lockoutWindow)).Error; err != nil {
		t.Fatal(err)
	}
	if w := e.loginWith(t, u.Email, testPassword); w.Code != http.StatusOK {
		t.Fatalf("after the window: %d", w.Code)
	}
}

// Locking only real accounts would reveal which addresses have one.
func TestUnknownAddressLocksOutLikeAKnownOne(t *testing.T) {
	e := newEnv(t)
	known := e.addUser(t, entities.RoleUser)
	var knownBody, unknownBody string
	for i := 0; i < 4; i++ {
		knownBody = e.loginWith(t, known.Email, "not-the-password").Body.String()
		unknownBody = e.loginWith(t, "nobody@example.com", "not-the-password").Body.String()
	}
	if knownBody != unknownBody || !strings.Contains(knownBody, "account_locked") {
		t.Fatalf("known %s, unknown %s", knownBody, unknownBody)
	}
}

func TestSuccessfulLoginClearsTheCount(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	for round := 0; round < 3; round++ {
		for i := 0; i < 2; i++ {
			e.loginWith(t, u.Email, "not-the-password")
		}
		if w := e.loginWith(t, u.Email, testPassword); w.Code != http.StatusOK {
			t.Fatalf("round %d: %d", round, w.Code)
		}
	}
}

func TestResetClearsTheLockout(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	raw := e.requestResetToken(t, u)
	for i := 0; i < 3; i++ {
		e.loginWith(t, u.Email, "not-the-password")
	}
	if w := e.reset(t, raw, "a-brand-new-password"); w.Code != http.StatusOK {
		t.Fatalf("reset: %d", w.Code)
	}
	if w := e.loginWith(t, u.Email, "a-brand-new-password"); w.Code != http.StatusOK {
		t.Fatalf("login after reset: %d", w.Code)
	}
}

func TestGuessingTheCurrentPasswordCountsTowardLockout(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	tokens := e.login(t, u)
	for i := 0; i < 3; i++ {
		e.changePassword(t, tokens.AccessToken, "not-the-password", "a-brand-new-password")
	}
	if w := e.changePassword(t, tokens.AccessToken, testPassword, "a-brand-new-password"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestLockoutCanBeDisabled(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Cfg.AuthSecurity.LockoutThreshold = 0 })
	u := e.addUser(t, entities.RoleUser)
	for i := 0; i < 6; i++ {
		e.loginWith(t, u.Email, "not-the-password")
	}
	if w := e.loginWith(t, u.Email, testPassword); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
}

type failingMailer struct{}

func (failingMailer) Send(context.Context, string, string, string) error {
	return errors.New("smtp down")
}

// The password has already changed by then, so a dead mail server is not a failed request.
func TestPasswordChangeSurvivesAFailedNotification(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Mailer = failingMailer{} })
	u := e.addUser(t, entities.RoleUser)
	tokens := e.login(t, u)
	if w := e.changePassword(t, tokens.AccessToken, testPassword, "a-brand-new-password"); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
