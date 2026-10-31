package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

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

func (e *testEnv) enroll(t *testing.T, access string) (secret string, codes []string) {
	t.Helper()
	w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/start", access, "")
	if w.Code != http.StatusOK {
		t.Fatalf("enroll start: %d %s", w.Code, w.Body.String())
	}
	secret = decodeData[EnrollStartResponse](t, w).Secret
	w = e.request(http.MethodPost, "/v1/auth/mfa/enroll/confirm", access, mustJSON(t, MFACodeRequest{Code: totpNow(t, secret)}))
	if w.Code != http.StatusOK {
		t.Fatalf("enroll confirm: %d %s", w.Code, w.Body.String())
	}
	return secret, decodeData[BackupCodesResponse](t, w).BackupCodes
}

func totpNow(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
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

	w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/start", access, "")
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

	w = e.request(http.MethodPost, "/v1/auth/mfa/enroll/confirm", access, mustJSON(t, MFACodeRequest{Code: totpNow(t, start.Secret)}))
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

			w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/start", access, "")
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
	secret := decodeData[EnrollStartResponse](t, e.request(http.MethodPost, "/v1/auth/mfa/enroll/start", access, "")).Secret
	if err := e.db.Model(u).Update("mfa_pending_at", time.Now().Add(-time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/confirm", access, mustJSON(t, MFACodeRequest{Code: totpNow(t, secret)}))
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "enrollment_expired" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestEnrollingTwiceIsRefused(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	access := e.login(t, u).AccessToken
	e.enroll(t, access)
	if w := e.request(http.MethodPost, "/v1/auth/mfa/enroll/start", access, ""); w.Code != http.StatusConflict {
		t.Fatalf("%d", w.Code)
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

	w = e.verifyMFA(t, token, totpNow(t, secret))
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
	if w := e.verifyMFA(t, token, totpNow(t, secret)); w.Code != http.StatusOK {
		t.Fatalf("%d", w.Code)
	}
	w := e.verifyMFA(t, token, totpNow(t, secret))
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
	code := totpNow(t, secret)

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
	if w := e.verifyMFA(t, token, totpNow(t, secret)); w.Code != http.StatusUnauthorized {
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
	w := e.verifyMFA(t, token, totpNow(t, secret))
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
		if w := e.verifyMFA(t, e.challenge(t, u), totpNow(t, secret)); w.Code != http.StatusOK {
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

func TestConcurrentUseOfABackupCodeHasOneWinner(t *testing.T) {
	e := newEnv(t, func(d *Deps) { d.Cfg.AuthSecurity.LockoutThreshold = 0 })
	u, _, codes := e.enrolledUser(t, entities.RoleUser)
	const n = 5
	tokens := make([]string, n)
	for i := range tokens {
		tokens[i] = e.challenge(t, u)
	}
	results := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = e.verifyMFA(t, tokens[i], codes[1]).Code
		}()
	}
	wg.Wait()
	wins := 0
	for _, c := range results {
		if c == http.StatusOK {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("%d wins in %v", wins, results)
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
	if w := e.request(http.MethodPost, "/v1/auth/mfa/backup-codes/regenerate", tokens.AccessToken, mustJSON(t, MFACodeRequest{Code: "000000"})); w.Code != http.StatusBadRequest {
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
	if w := e.request(http.MethodPost, "/v1/auth/mfa/backup-codes/regenerate", tokens.AccessToken, mustJSON(t, MFACodeRequest{Code: "000000"})); w.Code != http.StatusForbidden {
		t.Fatalf("wrong code: %d", w.Code)
	}
	w := e.request(http.MethodPost, "/v1/auth/mfa/backup-codes/regenerate", tokens.AccessToken, mustJSON(t, MFACodeRequest{Code: totpNow(t, secret)}))
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
	w := e.verifyMFA(t, challenge.MFAToken, totpNow(t, secret))
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

	w := e.adminReset(t, adminTokens.AccessToken, target.UUID.String(), totpNow(t, adminSecret))
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
	if w := e.adminReset(t, adminTokens.AccessToken, uuidMissing, totpNow(t, secret)); w.Code != http.StatusNotFound {
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
	if w := e.verifyMFA(t, e.challenge(t, u), totpNow(t, secret)); w.Code != http.StatusUnauthorized {
		t.Fatalf("%d", w.Code)
	}
	if w := e.verifyMFA(t, e.challenge(t, u), codes[0]); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
