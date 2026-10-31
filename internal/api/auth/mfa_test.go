package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/mfa"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	appcrypto "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/crypto"
	"github.com/pquerna/otp/totp"
	"golang.org/x/oauth2"
)

func (e *testEnv) enrollStart(t *testing.T, access string) *httptest.ResponseRecorder {
	t.Helper()
	return e.request(http.MethodPost, "/v1/auth/mfa/enroll/start", access, mustJSON(t, MFAEnrollStartRequest{CurrentPassword: testPassword}))
}

func (e *testEnv) regenerate(t *testing.T, access, password, code string) *httptest.ResponseRecorder {
	t.Helper()
	return e.request(http.MethodPost, "/v1/auth/mfa/backup-codes/regenerate", access, mustJSON(t, MFARegenerateRequest{CurrentPassword: password, Code: code}))
}

func (e *testEnv) enroll(t *testing.T, access string) (secret string, codes []string) {
	t.Helper()
	w := e.enrollStart(t, access)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll start: %d %s", w.Code, w.Body.String())
	}
	secret = decodeData[EnrollStartResponse](t, w).Secret
	w = e.request(http.MethodPost, "/v1/auth/mfa/enroll/confirm", access, mustJSON(t, MFACodeRequest{Code: e.code(t, secret)}))
	if w.Code != http.StatusOK {
		t.Fatalf("enroll confirm: %d %s", w.Code, w.Body.String())
	}
	return secret, decodeData[BackupCodesResponse](t, w).BackupCodes
}

func totpNow(t *testing.T, secret string) string {
	t.Helper()
	return totpAt(t, secret, time.Now())
}

func totpAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// code returns a usable TOTP code. A test cannot wait out a 30-second step between
// sign-ins, so this forgets the replay guard's stored step first. The tests of that guard
// use totpNow, which leaves it in place.
func (e *testEnv) code(t *testing.T, secret string) string {
	t.Helper()
	if err := e.db.Exec(`UPDATE users SET totp_last_step = NULL`).Error; err != nil {
		t.Fatal(err)
	}
	return totpNow(t, secret)
}

// challenge signs in with the password and returns the MFA token.
func (e *testEnv) challenge(t *testing.T, u *user.User) string {
	t.Helper()
	w := e.loginWith(t, u.Email, testPassword)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	c := decodeData[MFAChallengeResponse](t, w)
	if c.Status != statusMFARequired || c.MFAToken == "" {
		t.Fatalf("expected a challenge, got %s", w.Body.String())
	}
	return c.MFAToken
}

func (e *testEnv) verifyMFA(t *testing.T, token, code string) *httptest.ResponseRecorder {
	t.Helper()
	return e.request(http.MethodPost, "/v1/auth/mfa/verify", "", mustJSON(t, MFAVerifyRequest{MFAToken: token, Code: code}))
}

// enrolledUser returns a user with MFA on.
func (e *testEnv) enrolledUser(t *testing.T, role entities.Role) (*user.User, string, []string) {
	t.Helper()
	u := e.addUser(t, role)
	secret, codes := e.enroll(t, e.login(t, u).AccessToken)
	return u, secret, codes
}

func TestEnrollmentStoresTheSecretEncrypted(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	access := e.login(t, u).AccessToken

	w := e.enrollStart(t, access)
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	start := decodeData[EnrollStartResponse](t, w)
	if !strings.HasPrefix(start.OtpauthURI, "otpauth://totp/") || !strings.HasPrefix(start.QR, "data:image/png;base64,") {
		t.Fatalf("%+v", start)
	}

	var pending user.User
	if err := e.db.First(&pending, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if pending.MFAEnrolledAt != nil {
		t.Fatal("MFA must stay off until a code confirms it")
	}
	if pending.MFAPendingSecretEnc == "" || strings.Contains(pending.MFAPendingSecretEnc, start.Secret) {
		t.Fatalf("pending secret stored as %q", pending.MFAPendingSecretEnc)
	}
	// Starting has not turned anything on, so the password alone still signs in.
	if w := e.loginWith(t, u.Email, testPassword); !strings.Contains(w.Body.String(), "access_token") {
		t.Fatalf("login after start: %s", w.Body.String())
	}

	if w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/confirm", access, mustJSON(t, MFACodeRequest{Code: "000000"})); w.Code != http.StatusBadRequest {
		t.Fatalf("wrong first code: %d", w.Code)
	}

	w = e.request(http.MethodPost, "/v1/auth/mfa/enroll/confirm", access, mustJSON(t, MFACodeRequest{Code: e.code(t, start.Secret)}))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	codes := decodeData[BackupCodesResponse](t, w).BackupCodes
	if len(codes) != backupCodeTestCount {
		t.Fatalf("%d codes", len(codes))
	}

	var after user.User
	if err := e.db.First(&after, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.MFAEnrolledAt == nil || after.MFAPendingSecretEnc != "" || after.MFAPendingAt != nil {
		t.Fatalf("%+v", after)
	}
	if strings.Contains(after.TOTPSecretEnc, start.Secret) {
		t.Fatal("the secret is stored in the clear")
	}
	key, err := appcrypto.DeriveKey(testMFAKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := appcrypto.Decrypt(key, after.TOTPSecretEnc); err != nil || got != start.Secret {
		t.Fatalf("decrypted %q, %v", got, err)
	}

	var stored []mfa.BackupCode
	if err := e.db.Find(&stored).Error; err != nil {
		t.Fatal(err)
	}
	for _, c := range codes {
		for _, row := range stored {
			if strings.Contains(row.CodeHash, c) {
				t.Fatal("a backup code is stored in the clear")
			}
		}
	}
	if n := e.countEvents(t, audit.EventMFAEnrolled); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
	for _, row := range e.auditEvents(t) {
		if strings.Contains(row.Detail, start.Secret) {
			t.Fatal("the secret reached the audit trail")
		}
	}
}

func TestEnrollmentIsRefusedWithoutAUsableKey(t *testing.T) {
	for name, key := range map[string]string{"no key": "", "short key": "too-short"} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(d *Deps) { d.Cfg.MFA.EncryptionKey = key })
			u := e.addUser(t, entities.RoleUser)
			access := e.login(t, u).AccessToken

			w := e.enrollStart(t, access)
			if w.Code != http.StatusServiceUnavailable || errorCode(t, w) != "mfa_unavailable" {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/confirm", access, mustJSON(t, MFACodeRequest{Code: "123456"})); w.Code != http.StatusServiceUnavailable {
				t.Fatalf("confirm: %d", w.Code)
			}
			var after user.User
			if err := e.db.First(&after, u.ID).Error; err != nil {
				t.Fatal(err)
			}
			if after.MFAPendingSecretEnc != "" || after.TOTPSecretEnc != "" {
				t.Fatal("a secret was stored with no key to protect it")
			}
		})
	}
}

func TestEnrollmentExpires(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	access := e.login(t, u).AccessToken
	secret := decodeData[EnrollStartResponse](t, e.enrollStart(t, access)).Secret
	if err := e.db.Model(u).Update("mfa_pending_at", time.Now().Add(-time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/confirm", access, mustJSON(t, MFACodeRequest{Code: e.code(t, secret)}))
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "enrollment_expired" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestEnrollingTwiceIsRefused(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	access := e.login(t, u).AccessToken
	e.enroll(t, access)
	if w := e.enrollStart(t, access); w.Code != http.StatusConflict {
		t.Fatalf("%d", w.Code)
	}
}

func TestEnrollmentNeedsTheCurrentPassword(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	access := e.login(t, u).AccessToken

	cases := []struct {
		name, body, code string
	}{
		{"no body", "", apierr.CodeFieldRequired},
		{"no password", `{}`, apierr.CodeFieldRequired},
		{"wrong password", mustJSON(t, MFAEnrollStartRequest{CurrentPassword: "not-the-password"}), "current_password_incorrect"},
	}
	for _, tc := range cases {
		w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/start", access, tc.body)
		if w.Code != http.StatusBadRequest || errorCode(t, w) != tc.code {
			t.Errorf("%s: %d %s", tc.name, w.Code, w.Body.String())
		}
	}
	var after user.User
	if err := e.db.First(&after, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.MFAPendingSecretEnc != "" {
		t.Fatal("a secret was staged without re-authentication")
	}
	if w := e.enrollStart(t, access); w.Code != http.StatusOK {
		t.Fatalf("right password: %d %s", w.Code, w.Body.String())
	}
}

func TestWrongPasswordAtEnrollmentCountsTowardLockout(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	access := e.login(t, u).AccessToken
	body := mustJSON(t, MFAEnrollStartRequest{CurrentPassword: "not-the-password"})
	for i := 0; i < 3; i++ {
		e.request(http.MethodPost, "/v1/auth/mfa/enroll/start", access, body)
	}
	if w := e.enrollStart(t, access); w.Code != http.StatusTooManyRequests {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

// With no password to ask for, only a session signed in moments ago may do this.
func TestGoogleOnlyAccountNeedsARecentSignIn(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	tokens := e.login(t, u)
	if err := e.db.Model(u).Update("password_hash", "").Error; err != nil {
		t.Fatal(err)
	}

	if w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/start", tokens.AccessToken, ""); w.Code != http.StatusOK {
		t.Fatalf("a recent sign-in: %d %s", w.Code, w.Body.String())
	}

	s := e.sessionByRefresh(t, tokens.RefreshToken)
	if err := e.db.Model(s).UpdateColumn("created_at", time.Now().Add(-reauthWindow-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/start", tokens.AccessToken, "")
	if w.Code != http.StatusForbidden || errorCode(t, w) != "reauthentication_required" {
		t.Fatalf("an old session: %d %s", w.Code, w.Body.String())
	}

	// Refreshing must not make a stolen session look recent.
	refreshed := decodeData[AuthResponse](t, e.refresh(t, tokens.RefreshToken)).Tokens
	if w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/start", refreshed.AccessToken, ""); w.Code != http.StatusForbidden {
		t.Fatalf("a refreshed session: %d", w.Code)
	}
}

func TestSecurityChangesAreEmailed(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	access := e.login(t, u).AccessToken
	secret, _ := e.enroll(t, access)
	if m := e.mailer.last(t); m.to != u.Email || !strings.Contains(m.subject, "turned on") {
		t.Fatalf("enrollment notice: %+v", m)
	}
	if strings.Contains(e.mailer.last(t).body, secret) {
		t.Fatal("the secret was emailed")
	}
	w := e.regenerate(t, access, testPassword, e.code(t, secret))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	m := e.mailer.last(t)
	if m.to != u.Email || !strings.Contains(m.subject, "backup codes") {
		t.Fatalf("regeneration notice: %+v", m)
	}
	for _, c := range decodeData[BackupCodesResponse](t, w).BackupCodes {
		if strings.Contains(m.body, c) {
			t.Fatal("a backup code was emailed")
		}
	}
}

func TestRegeneratingNeedsThePasswordAndTheDevice(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	access := e.login(t, u).AccessToken
	secret, codes := e.enroll(t, access)

	if w := e.regenerate(t, access, "", e.code(t, secret)); w.Code != http.StatusBadRequest {
		t.Fatalf("no password: %d", w.Code)
	}
	if w := e.regenerate(t, access, "not-the-password", e.code(t, secret)); w.Code != http.StatusBadRequest || errorCode(t, w) != "current_password_incorrect" {
		t.Fatalf("wrong password: %d %s", w.Code, w.Body.String())
	}
	if w := e.regenerate(t, access, testPassword, "000000"); w.Code != http.StatusForbidden {
		t.Fatalf("wrong code: %d", w.Code)
	}
	// Nothing was replaced by any of those.
	if w := e.verifyMFA(t, e.challenge(t, u), codes[0]); w.Code != http.StatusOK {
		t.Fatalf("an old code should still work: %d %s", w.Code, w.Body.String())
	}
}

func TestMatchTOTPStep(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	now := time.Unix(1700000010, 0)
	step := now.Unix() / totpPeriod
	cases := []struct {
		name string
		at   time.Time
		want int64
		ok   bool
	}{
		{"this step", now, step, true},
		{"one step back", now.Add(-totpPeriod * time.Second), step - 1, true},
		{"one step ahead", now.Add(totpPeriod * time.Second), step + 1, true},
		{"two steps back", now.Add(-2 * totpPeriod * time.Second), 0, false},
		{"two steps ahead", now.Add(2 * totpPeriod * time.Second), 0, false},
	}
	for _, tc := range cases {
		got, ok := matchTOTPStep(secret, totpAt(t, secret, tc.at), now)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: step %d ok %v, want %d %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
	if _, ok := matchTOTPStep(secret, "not-a-code", now); ok {
		t.Error("garbage matched")
	}
}

func TestCodeUsedAtEnrollmentCannotSignIn(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	access := e.login(t, u).AccessToken
	secret := decodeData[EnrollStartResponse](t, e.enrollStart(t, access)).Secret
	code := totpNow(t, secret)
	if w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/confirm", access, mustJSON(t, MFACodeRequest{Code: code})); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var after user.User
	if err := e.db.First(&after, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.TOTPLastStep == nil {
		t.Fatal("enrollment did not record the step")
	}
	w := e.verifyMFA(t, e.challenge(t, u), code)
	if w.Code != http.StatusUnauthorized || errorCode(t, w) != "invalid_code" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestTOTPCodeCannotBeReplayed(t *testing.T) {
	e := newEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	code := e.code(t, secret)
	if w := e.verifyMFA(t, e.challenge(t, u), code); w.Code != http.StatusOK {
		t.Fatalf("first use: %d %s", w.Code, w.Body.String())
	}
	token := e.challenge(t, u)
	w := e.verifyMFA(t, token, code)
	if w.Code != http.StatusUnauthorized || errorCode(t, w) != "invalid_code" {
		t.Fatalf("replay: %d %s", w.Code, w.Body.String())
	}
	if n := e.countEvents(t, audit.EventMFAFailed); n != 1 {
		t.Fatalf("%d failed events", n)
	}
	// A refused replay does not spend the challenge: the next step's code still works.
	if w := e.verifyMFA(t, token, totpAt(t, secret, time.Now().Add(totpPeriod*time.Second))); w.Code != http.StatusOK {
		t.Fatalf("a later code: %d %s", w.Code, w.Body.String())
	}
}

// A step can never go backwards, so a code from before the last accepted one is refused
// even though it is still inside the skew window and has never been used.
func TestEarlierStepIsRefusedAfterALaterOne(t *testing.T) {
	e := newEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	if err := e.db.Exec(`UPDATE users SET totp_last_step = NULL`).Error; err != nil {
		t.Fatal(err)
	}
	later := totpAt(t, secret, time.Now().Add(totpPeriod*time.Second))
	if w := e.verifyMFA(t, e.challenge(t, u), later); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := e.verifyMFA(t, e.challenge(t, u), totpNow(t, secret)); w.Code != http.StatusUnauthorized {
		t.Fatalf("an earlier step: %d %s", w.Code, w.Body.String())
	}
}

func TestStepUpCodeCannotBeReplayed(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	access := e.login(t, u).AccessToken
	secret, _ := e.enroll(t, access)
	code := e.code(t, secret)
	if w := e.regenerate(t, access, testPassword, code); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := e.regenerate(t, access, testPassword, code); w.Code != http.StatusForbidden {
		t.Fatalf("replay: %d %s", w.Code, w.Body.String())
	}
}

func TestNewChallengeRetiresTheOldOne(t *testing.T) {
	e := newEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	old := e.challenge(t, u)
	current := e.challenge(t, u)
	w := e.verifyMFA(t, old, e.code(t, secret))
	if w.Code != http.StatusUnauthorized || errorCode(t, w) != "mfa_session_expired" {
		t.Fatalf("old challenge: %d %s", w.Code, w.Body.String())
	}
	if w := e.verifyMFA(t, current, e.code(t, secret)); w.Code != http.StatusOK {
		t.Fatalf("current challenge: %d %s", w.Code, w.Body.String())
	}
	var live int64
	if err := e.db.Model(&mfa.Challenge{}).Where("user_id = ? AND consumed_at IS NULL", u.ID).Count(&live).Error; err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("%d live challenges", live)
	}
}

// Parallel guesses must not all pass a check made before any of them is counted.
func TestParallelBadCodesStayWithinTheThreshold(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Cfg.MFA.MaxAttempts = 100 }) // the account limit is under test
	u, _, _ := e.enrolledUser(t, entities.RoleUser)
	token := e.challenge(t, u)

	const n = 12
	var checked, locked atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch w := e.verifyMFA(t, token, "000000"); errorCode(t, w) {
			case "invalid_code":
				checked.Add(1)
			case "account_locked":
				locked.Add(1)
			default:
				t.Errorf("%d %s", w.Code, w.Body.String())
			}
		}()
	}
	wg.Wait()
	if checked.Load() != testLockoutThreshold || locked.Load() != n-testLockoutThreshold {
		t.Fatalf("%d codes checked and %d refused, with a threshold of %d", checked.Load(), locked.Load(), testLockoutThreshold)
	}
}

func TestParallelBadPasswordsStayWithinTheThreshold(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	const n = 12
	var checked atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if w := e.loginWith(t, u.Email, "not-the-password"); w.Code == http.StatusUnauthorized {
				checked.Add(1)
			}
		}()
	}
	wg.Wait()
	if checked.Load() != testLockoutThreshold {
		t.Fatalf("%d passwords checked, with a threshold of %d", checked.Load(), testLockoutThreshold)
	}
}

func TestBurstOfCorrectPasswordsLeavesNoLockout(t *testing.T) {
	e := newEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.loginWith(t, u.Email, testPassword)
		}()
	}
	wg.Wait()
	if w := e.verifyMFA(t, e.challenge(t, u), e.code(t, secret)); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

// Refused attempts give their slot back, and that must not reopen the door: once the
// threshold's worth of guesses have failed, every further one is refused unchecked.
func TestRefusedAttemptsDoNotReopenTheLock(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	for i := 0; i < testLockoutThreshold; i++ {
		if w := e.loginWith(t, u.Email, "not-the-password"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	for i := 0; i < 5; i++ {
		if w := e.loginWith(t, u.Email, testPassword); w.Code != http.StatusTooManyRequests {
			t.Fatalf("refusal %d: %d %s", i, w.Code, w.Body.String())
		}
	}
}

// A good password gives its attempt back, so signing in does not itself burn the count.
func TestCorrectPasswordDoesNotCountAgainstAnEnrolledUser(t *testing.T) {
	e := newEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	for i := 0; i < 6; i++ {
		e.challenge(t, u)
	}
	if w := e.verifyMFA(t, e.challenge(t, u), e.code(t, secret)); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestEnrollingSignsOutOtherSessions(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	here, there := e.login(t, u), e.login(t, u)
	e.enroll(t, here.AccessToken)
	if !e.securedOK(t, here.AccessToken) {
		t.Fatal("the current session must survive")
	}
	if e.securedOK(t, there.AccessToken) {
		t.Fatal("a session that predates MFA must not survive it")
	}
}

func TestLoginWithMFA(t *testing.T) {
	e := newEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)

	w := e.loginWith(t, u.Email, testPassword)
	if w.Code != http.StatusOK {
		t.Fatalf("%d", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "access_token") || strings.Contains(body, "refresh_token") {
		t.Fatalf("a password alone must not yield tokens: %s", body)
	}
	token := decodeData[MFAChallengeResponse](t, w).MFAToken

	w = e.verifyMFA(t, token, e.code(t, secret))
	if w.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}
	tokens := decodeData[AuthResponse](t, w).Tokens
	if !e.securedOK(t, tokens.AccessToken) {
		t.Fatal("access token refused")
	}
	if s := e.sessionByRefresh(t, tokens.RefreshToken); s.LoginMethod != session.MethodPassword {
		t.Fatalf("method %q", s.LoginMethod)
	}
	if n := e.countEvents(t, audit.EventMFAVerified); n != 1 {
		t.Fatalf("%d verified events", n)
	}
}

func TestMFATokenCannotReachSecuredRoutes(t *testing.T) {
	e := newEnv(t)
	u, _, _ := e.enrolledUser(t, entities.RoleUser)
	token := e.challenge(t, u)

	if e.securedOK(t, token) {
		t.Fatal("an MFA token passed UserAuth")
	}
	if w := e.request(http.MethodGet, "/v1/auth/sessions", token, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("sessions: %d", w.Code)
	}
	if w := e.refresh(t, token); w.Code != http.StatusUnauthorized {
		t.Fatalf("refresh: %d", w.Code)
	}
}

func TestChallengeIsSingleUse(t *testing.T) {
	e := newEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	token := e.challenge(t, u)
	if w := e.verifyMFA(t, token, e.code(t, secret)); w.Code != http.StatusOK {
		t.Fatalf("%d", w.Code)
	}
	w := e.verifyMFA(t, token, e.code(t, secret))
	if w.Code != http.StatusUnauthorized || errorCode(t, w) != "mfa_session_expired" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestConcurrentVerificationsYieldOneSession(t *testing.T) {
	e := newEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	token := e.challenge(t, u)
	var before int64
	if err := e.db.Model(&session.Session{}).Count(&before).Error; err != nil {
		t.Fatal(err)
	}
	code := e.code(t, secret)

	const n = 5
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = e.verifyMFA(t, token, code).Code
		}()
	}
	wg.Wait()

	wins := 0
	for _, c := range codes {
		if c == http.StatusOK {
			wins++
		}
	}
	var after int64
	if err := e.db.Model(&session.Session{}).Count(&after).Error; err != nil {
		t.Fatal(err)
	}
	if wins != 1 || after != before+1 {
		t.Fatalf("%d wins, %d new sessions in %v", wins, after-before, codes)
	}
}

func TestChallengeExpires(t *testing.T) {
	e := newEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	token := e.challenge(t, u)
	if err := e.db.Model(&mfa.Challenge{}).Where("token_hash = ?", platformauth.HashToken(token)).
		Update("expires_at", time.Now().UTC().Add(-time.Minute)).Error; err != nil {
		t.Fatal(err)
	}
	if w := e.verifyMFA(t, token, e.code(t, secret)); w.Code != http.StatusUnauthorized {
		t.Fatalf("%d", w.Code)
	}
}

func TestChallengeAttemptsAreCapped(t *testing.T) {
	e := newEnv(t, func(d *Deps) {
		d.Cfg.AuthSecurity.LockoutThreshold = 0 // this test is about the challenge's own limit
		d.Cfg.MFA.MaxAttempts = 3
	})
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	token := e.challenge(t, u)
	for i := 0; i < 3; i++ {
		if w := e.verifyMFA(t, token, "000000"); w.Code != http.StatusUnauthorized || errorCode(t, w) != "invalid_code" {
			t.Fatalf("attempt %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	w := e.verifyMFA(t, token, e.code(t, secret))
	if w.Code != http.StatusUnauthorized || errorCode(t, w) != "mfa_session_expired" {
		t.Fatalf("the right code after the cap: %d %s", w.Code, w.Body.String())
	}
}

// Signing in again with the password must not buy more guesses at the code.
func TestWrongCodesCountTowardLockoutAcrossChallenges(t *testing.T) {
	e := newEnv(t)
	u, _, _ := e.enrolledUser(t, entities.RoleUser)
	for i := 0; i < 3; i++ {
		if w := e.verifyMFA(t, e.challenge(t, u), "000000"); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
	if w := e.loginWith(t, u.Email, testPassword); w.Code != http.StatusTooManyRequests {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
}

func TestPassingMFAClearsTheFailureCount(t *testing.T) {
	e := newEnv(t)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	for round := 0; round < 3; round++ {
		e.verifyMFA(t, e.challenge(t, u), "000000")
		e.verifyMFA(t, e.challenge(t, u), "000000")
		if w := e.verifyMFA(t, e.challenge(t, u), e.code(t, secret)); w.Code != http.StatusOK {
			t.Fatalf("round %d: %d %s", round, w.Code, w.Body.String())
		}
	}
}

func TestBackupCodeIsSingleUse(t *testing.T) {
	e := newEnv(t)
	u, _, codes := e.enrolledUser(t, entities.RoleUser)

	w := e.verifyMFA(t, e.challenge(t, u), codes[0])
	if w.Code != http.StatusOK {
		t.Fatalf("first use: %d %s", w.Code, w.Body.String())
	}
	if n := e.countEvents(t, audit.EventMFABackupUsed); n != 1 {
		t.Fatalf("%d backup events", n)
	}
	w = e.verifyMFA(t, e.challenge(t, u), codes[0])
	if w.Code != http.StatusUnauthorized || errorCode(t, w) != "invalid_code" {
		t.Fatalf("second use: %d %s", w.Code, w.Body.String())
	}
	var stored mfa.BackupCode
	if err := e.db.Where("code_hash = ?", hashBackupCode(codes[0])).First(&stored).Error; err != nil {
		t.Fatal(err)
	}
	if stored.UsedAt == nil {
		t.Fatal("code not marked used")
	}
}

// Driven at the service, because a user only ever has one live challenge, and that alone
// would serialize these before the code's own compare-and-set was reached.
func TestConcurrentUseOfABackupCodeHasOneWinner(t *testing.T) {
	e := newEnv(t)
	svc := NewService(e.deps)
	u, _, codes := e.enrolledUser(t, entities.RoleUser)
	const n = 5
	wins := make([]bool, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := svc.consumeBackupCode(context.Background(), u.ID, codes[1])
			if err != nil {
				t.Error(err)
			}
			wins[i] = ok
		}()
	}
	wg.Wait()
	won := 0
	for _, ok := range wins {
		if ok {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d wins", won)
	}
}

func TestBackupCodeIsAcceptedHoweverItIsTyped(t *testing.T) {
	e := newEnv(t)
	u, _, codes := e.enrolledUser(t, entities.RoleUser)
	typed := strings.ToLower(strings.ReplaceAll(codes[2], "-", " "))
	if w := e.verifyMFA(t, e.challenge(t, u), typed); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestBackupCodesBelongToOneUser(t *testing.T) {
	e := newEnv(t)
	_, _, codes := e.enrolledUser(t, entities.RoleUser)
	other, _, _ := e.enrolledUser(t, entities.RoleUser)
	if w := e.verifyMFA(t, e.challenge(t, other), codes[0]); w.Code != http.StatusUnauthorized {
		t.Fatalf("another user's code: %d", w.Code)
	}
}

func TestGeneratedBackupCodesHaveTheDocumentedShape(t *testing.T) {
	shape := regexp.MustCompile(`^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$`)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		c, err := generateBackupCode()
		if err != nil {
			t.Fatal(err)
		}
		if !shape.MatchString(c) || seen[c] {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
	}
}

func TestStatusAndRegenerate(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	tokens := e.login(t, u)

	status := func(access string) *MFAStatusResponse {
		t.Helper()
		w := e.request(http.MethodGet, "/v1/auth/mfa/status", access, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%d", w.Code)
		}
		return decodeData[MFAStatusResponse](t, w)
	}
	if s := status(tokens.AccessToken); s.Enabled || s.BackupCodesRemaining != 0 {
		t.Fatalf("%+v", s)
	}
	if w := e.regenerate(t, tokens.AccessToken, testPassword, "000000"); w.Code != http.StatusBadRequest {
		t.Fatalf("not enrolled: %d", w.Code)
	}

	secret, codes := e.enroll(t, tokens.AccessToken)
	if s := status(tokens.AccessToken); !s.Enabled || s.EnrolledAt == nil || s.BackupCodesRemaining != backupCodeTestCount || s.BackupCodesTotal != backupCodeTestCount {
		t.Fatalf("%+v", s)
	}

	withBackup := decodeData[AuthResponse](t, e.verifyMFA(t, e.challenge(t, u), codes[0])).Tokens
	if s := status(withBackup.AccessToken); s.BackupCodesRemaining != backupCodeTestCount-1 {
		t.Fatalf("%+v", s)
	}

	// A stolen access token alone must not be able to mint a permanent second factor.
	if w := e.regenerate(t, tokens.AccessToken, testPassword, "000000"); w.Code != http.StatusForbidden {
		t.Fatalf("wrong code: %d", w.Code)
	}
	w := e.regenerate(t, tokens.AccessToken, testPassword, e.code(t, secret))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	fresh := decodeData[BackupCodesResponse](t, w).BackupCodes
	if s := status(tokens.AccessToken); s.BackupCodesRemaining != backupCodeTestCount {
		t.Fatalf("%+v", s)
	}
	if w := e.verifyMFA(t, e.challenge(t, u), codes[1]); w.Code != http.StatusUnauthorized {
		t.Fatalf("a replaced code still works: %d", w.Code)
	}
	if w := e.verifyMFA(t, e.challenge(t, u), fresh[0]); w.Code != http.StatusOK {
		t.Fatalf("a new code failed: %d", w.Code)
	}
	if n := e.countEvents(t, audit.EventMFABackupRegenerated); n != 1 {
		t.Fatalf("%d audit rows", n)
	}
}

func TestPasswordResetDoesNotBypassMFA(t *testing.T) {
	const next = "a-brand-new-password"
	e := newEnv(t)
	u, _, _ := e.enrolledUser(t, entities.RoleUser)
	raw := e.requestResetToken(t, u)
	if w := e.reset(t, raw, next); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w := e.loginWith(t, u.Email, next)
	if strings.Contains(w.Body.String(), "access_token") || !strings.Contains(w.Body.String(), statusMFARequired) {
		t.Fatalf("an emailed link bypassed MFA: %s", w.Body.String())
	}
}

func TestGoogleLoginStillNeedsTheSecondFactor(t *testing.T) {
	e := newEnv(t)
	svc := NewService(e.deps)
	u, secret, _ := e.enrolledUser(t, entities.RoleUser)
	if err := e.db.Model(u).Update("google_id", "g-2").Error; err != nil {
		t.Fatal(err)
	}
	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"google-token","token_type":"bearer"}`))
	}))
	defer oauthServer.Close()
	svc.googleOAuth = &oauth2.Config{ClientID: "id", Endpoint: oauth2.Endpoint{TokenURL: oauthServer.URL}}
	svc.fetchGoogleUser = func(context.Context, *http.Client) (*googleUserInfo, error) {
		return &googleUserInfo{ID: "g-2", Email: u.Email, Name: "G"}, nil
	}

	resp, challenge, err := svc.GoogleCallback(context.Background(), "code", LoginContext{})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil || challenge == nil {
		t.Fatalf("google alone yielded a session: %+v", resp)
	}
	w := e.verifyMFA(t, challenge.MFAToken, e.code(t, secret))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	tokens := decodeData[AuthResponse](t, w).Tokens
	if s := e.sessionByRefresh(t, tokens.RefreshToken); s.LoginMethod != session.MethodGoogle {
		t.Fatalf("method %q", s.LoginMethod)
	}
}

func (e *testEnv) adminReset(t *testing.T, access, target, code string) *httptest.ResponseRecorder {
	t.Helper()
	return e.request(http.MethodPost, "/v1/admin/users/"+target+"/mfa/reset", access, mustJSON(t, AdminResetMFARequest{StepUpCode: code}))
}

func TestAdminResetClearsTheTargetsSecondFactor(t *testing.T) {
	e := newEnv(t)
	admin := e.addUser(t, entities.RoleAdmin)
	adminTokens := e.login(t, admin)
	adminSecret, _ := e.enroll(t, adminTokens.AccessToken)

	target, _, codes := e.enrolledUser(t, entities.RoleUser)
	targetSession := e.verifyMFA(t, e.challenge(t, target), codes[0])
	targetTokens := decodeData[AuthResponse](t, targetSession).Tokens

	w := e.adminReset(t, adminTokens.AccessToken, target.UUID.String(), e.code(t, adminSecret))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}

	var after user.User
	if err := e.db.First(&after, target.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.MFAEnrolledAt != nil || after.TOTPSecretEnc != "" {
		t.Fatalf("%+v", after)
	}
	var left int64
	if err := e.db.Unscoped().Model(&mfa.BackupCode{}).Where("user_id = ?", target.ID).Count(&left).Error; err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("%d backup codes left", left)
	}
	if e.securedOK(t, targetTokens.AccessToken) {
		t.Fatal("the target must be signed out")
	}
	if w := e.loginWith(t, target.Email, testPassword); !strings.Contains(w.Body.String(), "access_token") {
		t.Fatalf("password should now be enough: %s", w.Body.String())
	}
	if m := e.mailer.last(t); m.to != target.Email {
		t.Fatalf("notice went to %q", m.to)
	}
	var row audit.Log
	if err := e.db.Where("event = ?", audit.EventMFAReset).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.ActorUserID == nil || *row.ActorUserID != admin.ID || !strings.Contains(row.Detail, target.UUID.String()) {
		t.Fatalf("%+v", row)
	}
}

func TestAdminResetMFARefusals(t *testing.T) {
	e := newEnv(t)
	target, _, _ := e.enrolledUser(t, entities.RoleUser)

	plainAdmin := e.login(t, e.addUser(t, entities.RoleAdmin))
	w := e.adminReset(t, plainAdmin.AccessToken, target.UUID.String(), "000000")
	if w.Code != http.StatusForbidden || errorCode(t, w) != "step_up_required" {
		t.Fatalf("admin without mfa: %d %s", w.Code, w.Body.String())
	}

	admin := e.addUser(t, entities.RoleAdmin)
	adminTokens := e.login(t, admin)
	secret, _ := e.enroll(t, adminTokens.AccessToken)
	if w := e.adminReset(t, adminTokens.AccessToken, target.UUID.String(), "000000"); w.Code != http.StatusForbidden {
		t.Fatalf("wrong step-up code: %d", w.Code)
	}
	if w := e.adminReset(t, adminTokens.AccessToken, uuidMissing, e.code(t, secret)); w.Code != http.StatusNotFound {
		t.Fatalf("unknown target: %d", w.Code)
	}

	for _, role := range []entities.Role{entities.RoleUser, entities.RoleSupport} {
		caller := e.login(t, e.addUser(t, role))
		if w := e.adminReset(t, caller.AccessToken, target.UUID.String(), "000000"); w.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", role, w.Code)
		}
	}

	var after user.User
	if err := e.db.First(&after, target.ID).Error; err != nil {
		t.Fatal(err)
	}
	if after.MFAEnrolledAt == nil {
		t.Fatal("a refused reset cleared the target's MFA")
	}
}

// A rotated key must not lock anyone out of the backup codes they were given.
func TestBackupCodesWorkWhenTheSecretCannotBeDecrypted(t *testing.T) {
	e := newEnv(t)
	u, secret, codes := e.enrolledUser(t, entities.RoleUser)
	if err := e.db.Model(u).Update("totp_secret_enc", "not-a-valid-ciphertext").Error; err != nil {
		t.Fatal(err)
	}
	if w := e.verifyMFA(t, e.challenge(t, u), e.code(t, secret)); w.Code != http.StatusUnauthorized {
		t.Fatalf("%d", w.Code)
	}
	if w := e.verifyMFA(t, e.challenge(t, u), codes[0]); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
