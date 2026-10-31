package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/google/uuid"
)

func (e *testEnv) impersonate(t *testing.T, access string, target *user.User) *ImpersonateResponse {
	t.Helper()
	w := e.request(http.MethodPost, "/v1/admin/users/"+target.UUID.String()+"/impersonate", access, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("impersonate: %d %s", w.Code, w.Body.String())
	}
	return decodeData[ImpersonateResponse](t, w)
}

func (e *testEnv) sessionByUUID(t *testing.T, sid string) *session.Session {
	t.Helper()
	id, err := uuid.Parse(sid)
	if err != nil {
		t.Fatal(err)
	}
	var s session.Session
	if err := e.db.Where("uuid = ?", id).First(&s).Error; err != nil {
		t.Fatal(err)
	}
	return &s
}

func TestStartImpersonation(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	adminTokens := e.login(t, admin)

	w := e.request(http.MethodPost, "/v1/admin/users/"+target.UUID.String()+"/impersonate", adminTokens.AccessToken, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "refresh_token") {
		t.Fatalf("a login-as session must have no refresh token: %s", w.Body.String())
	}
	resp := decodeData[ImpersonateResponse](t, w)
	if resp.Target.UUID != target.UUID.String() {
		t.Fatalf("%+v", resp.Target)
	}

	claims, err := platformauth.NewJWTVerifier(testSecret, "iss", "aud").Verify(resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != target.UUID.String() || claims.Impersonator != admin.ID || claims.SID != resp.SessionUUID {
		t.Fatalf("claims = %+v", claims)
	}
	if left := time.Until(claims.ExpiresAt); left > ImpersonationTTL || left < ImpersonationTTL-time.Minute {
		t.Fatalf("token lives %v", left)
	}

	s := e.sessionByUUID(t, resp.SessionUUID)
	if s.UserID != target.ID || s.ImpersonatorUserID == nil || *s.ImpersonatorUserID != admin.ID {
		t.Fatalf("session = %+v", s)
	}
	if s.LoginMethod != session.MethodImpersonation {
		t.Fatalf("method %q", s.LoginMethod)
	}
	if time.Until(s.AbsoluteExpiry) > ImpersonationTTL || !s.ExpiresAt.Equal(s.AbsoluteExpiry) {
		t.Fatalf("expiry: %v %v", s.ExpiresAt, s.AbsoluteExpiry)
	}

	// It acts as the target, with the target's role from the database.
	w = e.request(http.MethodGet, "/v1/auth/permissions", resp.AccessToken, "")
	if w.Code != http.StatusOK || decodeData[PermissionsResponse](t, w).Role != entities.RoleUser {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// The admin's own session is untouched.
	if !e.securedOK(t, adminTokens.AccessToken) {
		t.Fatal("the admin was signed out")
	}

	var row audit.Log
	if err := e.db.Where("event = ?", audit.EventImpersonationStarted).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.ActorUserID == nil || *row.ActorUserID != admin.ID || row.ImpersonatorUserID == nil || *row.ImpersonatorUserID != admin.ID {
		t.Fatalf("%+v", row)
	}
	if !strings.Contains(row.Detail, target.UUID.String()) || !strings.Contains(row.Detail, resp.SessionUUID) {
		t.Fatalf("detail: %s", row.Detail)
	}
	if strings.Contains(row.Detail, resp.AccessToken) {
		t.Fatal("the token reached the audit trail")
	}
}

func TestImpersonationSessionCannotRefresh(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	resp := e.impersonate(t, e.login(t, admin).AccessToken, target)

	if w := e.refresh(t, resp.AccessToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("the access token as a refresh token: %d", w.Code)
	}

	// Even if someone came to hold a matching token, the row itself refuses renewal.
	s := e.sessionByUUID(t, resp.SessionUUID)
	if s.RefreshTokenHash == "" {
		t.Fatal("an empty hash could be matched by an empty token")
	}
	const forged = "a-token-somehow-in-hand"
	if err := e.db.Model(s).Update("refresh_token_hash", platformauth.HashToken(forged)).Error; err != nil {
		t.Fatal(err)
	}
	if w := e.refresh(t, forged); w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
	if e.sessionByUUID(t, resp.SessionUUID).RevokedAt == nil {
		t.Fatal("the attempt should end the session")
	}
	if e.securedOK(t, resp.AccessToken) {
		t.Fatal("the session survived")
	}
}

func TestImpersonationCannotNest(t *testing.T) {
	e := newEnv(t)
	admin := e.addUser(t, entities.RoleAdmin)
	first, second := e.addUser(t, entities.RoleUser), e.addUser(t, entities.RoleUser)
	resp := e.impersonate(t, e.login(t, admin).AccessToken, first)

	path := "/v1/admin/users/" + second.UUID.String() + "/impersonate"
	if w := e.request(http.MethodPost, path, resp.AccessToken, ""); w.Code != http.StatusForbidden {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}

	// The bar must hold even if the impersonated user is promoted mid-session, so the
	// session's role has the capability and only the bar stands in the way.
	if err := e.db.Model(first).Update("platform_role", entities.RoleAdmin).Error; err != nil {
		t.Fatal(err)
	}
	if w := e.request(http.MethodPost, path, resp.AccessToken, ""); w.Code != http.StatusForbidden {
		t.Fatalf("promoted mid-session: %d %s", w.Code, w.Body.String())
	}
	var count int64
	if err := e.db.Model(&session.Session{}).Where("user_id = ?", second.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("a nested session was created")
	}
}

func TestImpersonationRefusals(t *testing.T) {
	e := newEnv(t)
	admin := e.addUser(t, entities.RoleAdmin)
	access := e.login(t, admin).AccessToken
	peer := e.addUser(t, entities.RoleAdmin)

	w := e.request(http.MethodPost, "/v1/admin/users/"+peer.UUID.String()+"/impersonate", access, "")
	if w.Code != http.StatusForbidden || errorCode(t, w) != "not_impersonatable" {
		t.Fatalf("an admin target: %d %s", w.Code, w.Body.String())
	}
	if n := e.countEvents(t, audit.EventImpersonationDenied); n != 1 {
		t.Fatalf("%d denied events", n)
	}

	w = e.request(http.MethodPost, "/v1/admin/users/"+admin.UUID.String()+"/impersonate", access, "")
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "self_action" {
		t.Fatalf("self: %d %s", w.Code, w.Body.String())
	}
	if n := e.countEvents(t, audit.EventImpersonationDenied); n != 2 {
		t.Fatalf("%d denied events", n)
	}

	for _, target := range []string{uuidMissing, "not-a-uuid"} {
		if w := e.request(http.MethodPost, "/v1/admin/users/"+target+"/impersonate", access, ""); w.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", target, w.Code)
		}
	}

	var count int64
	if err := e.db.Model(&session.Session{}).Where("impersonator_user_id IS NOT NULL").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("%d sessions opened by refused attempts", count)
	}
}

func TestOnlyAdminsMayImpersonate(t *testing.T) {
	e := newEnv(t)
	target := e.addUser(t, entities.RoleUser)
	path := "/v1/admin/users/" + target.UUID.String() + "/impersonate"
	for _, role := range []entities.Role{entities.RoleUser, entities.RoleSupport} {
		caller := e.login(t, e.addUser(t, role))
		if w := e.request(http.MethodPost, path, caller.AccessToken, ""); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", role, w.Code)
		}
	}
	if w := e.request(http.MethodPost, path, "", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", w.Code)
	}
}

func TestSupportUserCanBeImpersonated(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleSupport)
	resp := e.impersonate(t, e.login(t, admin).AccessToken, target)
	if !e.securedOK(t, resp.AccessToken) {
		t.Fatal("token refused")
	}
}

// Logout passes no impersonator to the recorder, so the id on this row can only have come
// from the request context that the auth middleware prepared.
func TestAuditRowsInsideTheSessionNameTheImpersonator(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	resp := e.impersonate(t, e.login(t, admin).AccessToken, target)

	if w := e.request(http.MethodPost, "/v1/auth/logout", resp.AccessToken, ""); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var row audit.Log
	if err := e.db.Where("event = ?", audit.EventLogout).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.ActorUserID == nil || *row.ActorUserID != target.ID {
		t.Fatalf("actor: %+v", row.ActorUserID)
	}
	if row.ImpersonatorUserID == nil || *row.ImpersonatorUserID != admin.ID {
		t.Fatalf("the row does not name the impersonator: %+v", row)
	}

	// And an ordinary session's row does not.
	plain := e.login(t, target)
	if w := e.request(http.MethodPost, "/v1/auth/logout", plain.AccessToken, ""); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	var rows []audit.Log
	if err := e.db.Where("event = ?", audit.EventLogout).Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[1].ImpersonatorUserID != nil {
		t.Fatalf("%+v", rows)
	}
}

func TestEndingAnImpersonationLeavesRealSessionsAlone(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	adminTokens := e.login(t, admin)
	targetTokens := e.login(t, target)
	resp := e.impersonate(t, adminTokens.AccessToken, target)

	if w := e.request(http.MethodPost, "/v1/auth/impersonate/end", resp.AccessToken, ""); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if e.securedOK(t, resp.AccessToken) {
		t.Fatal("the session should be over")
	}
	if !e.securedOK(t, targetTokens.AccessToken) || !e.securedOK(t, adminTokens.AccessToken) {
		t.Fatal("ending it must leave real sessions alone")
	}
	var row audit.Log
	if err := e.db.Where("event = ?", audit.EventImpersonationEnded).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.ImpersonatorUserID == nil || *row.ImpersonatorUserID != admin.ID || row.ActorUserID == nil || *row.ActorUserID != target.ID {
		t.Fatalf("%+v", row)
	}
}

func TestEndImpersonationRefusesAnOrdinarySession(t *testing.T) {
	e := newEnv(t)
	tokens := e.login(t, e.addUser(t, entities.RoleUser))
	w := e.request(http.MethodPost, "/v1/auth/impersonate/end", tokens.AccessToken, "")
	if w.Code != http.StatusBadRequest || errorCode(t, w) != "not_impersonating" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if !e.securedOK(t, tokens.AccessToken) {
		t.Fatal("the user was signed out")
	}
}

func TestImpersonationExpiresWithItsSession(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	resp := e.impersonate(t, e.login(t, admin).AccessToken, target)
	if err := e.db.Model(e.sessionByUUID(t, resp.SessionUUID)).
		Update("absolute_expiry", time.Now().UTC().Add(-time.Second)).Error; err != nil {
		t.Fatal(err)
	}
	if e.securedOK(t, resp.AccessToken) {
		t.Fatal("the session outlived its expiry")
	}
}

// An impersonator is there to see what the user sees, not to change their credentials.
func TestImpersonationIsBarredFromTheAccountsOwnSecurity(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	targetTokens := e.login(t, target)
	resp := e.impersonate(t, e.login(t, admin).AccessToken, target)
	otherSID := e.sessionByRefresh(t, targetTokens.RefreshToken).UUID.String()

	cases := []struct{ method, path, body string }{
		{http.MethodPost, "/v1/auth/change-password", mustJSON(t, ChangePasswordRequest{CurrentPassword: testPassword, NewPassword: "a-brand-new-password"})},
		{http.MethodDelete, "/v1/auth/sessions", ""},
		{http.MethodDelete, "/v1/auth/sessions/" + otherSID, ""},
		{http.MethodPost, "/v1/auth/mfa/enroll/start", ""},
		{http.MethodPost, "/v1/auth/mfa/enroll/confirm", mustJSON(t, MFACodeRequest{Code: "123456"})},
		{http.MethodPost, "/v1/auth/mfa/backup-codes/regenerate", mustJSON(t, MFACodeRequest{Code: "123456"})},
	}
	for _, tc := range cases {
		if w := e.request(tc.method, tc.path, resp.AccessToken, tc.body); w.Code != http.StatusForbidden {
			t.Errorf("%s %s: %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
		// The same routes must still work for the real user.
		if w := e.request(tc.method, tc.path, "", tc.body); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s anonymously: %d", tc.method, tc.path, w.Code)
		}
	}
	if !e.securedOK(t, targetTokens.AccessToken) {
		t.Fatal("the real user was signed out")
	}
	if w := e.loginWith(t, target.Email, testPassword); w.Code != http.StatusOK {
		t.Fatalf("the password changed: %d", w.Code)
	}
}

// The user can see that support access happened, and tell it from a compromise.
func TestSessionListLabelsImpersonation(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	targetTokens := e.login(t, target)
	resp := e.impersonate(t, e.login(t, admin).AccessToken, target)

	views := *decodeData[[]SessionView](t, e.request(http.MethodGet, "/v1/auth/sessions", targetTokens.AccessToken, ""))
	labelled := 0
	for _, v := range views {
		if v.Impersonated {
			labelled++
			if v.UUID != resp.SessionUUID {
				t.Fatalf("wrong session labelled: %+v", v)
			}
		}
	}
	if labelled != 1 || len(views) != 2 {
		t.Fatalf("%+v", views)
	}
}

func TestRevokingTheTargetsSessionsEndsTheImpersonation(t *testing.T) {
	const next = "a-brand-new-password"
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	targetTokens := e.login(t, target)
	resp := e.impersonate(t, e.login(t, admin).AccessToken, target)
	if w := e.changePassword(t, targetTokens.AccessToken, testPassword, next); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if e.securedOK(t, resp.AccessToken) {
		t.Fatal("the impersonation survived the user's password change")
	}
}

func TestRevokingTheImpersonatorsSessionsEndsTheImpersonation(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	adminTokens := e.login(t, admin)
	resp := e.impersonate(t, adminTokens.AccessToken, target)
	if w := e.changePassword(t, adminTokens.AccessToken, testPassword, "a-brand-new-password"); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if e.securedOK(t, resp.AccessToken) {
		t.Fatal("the impersonation survived the admin signing out everywhere")
	}
}

func TestStartRollsBackIfTheAuditRowCannotBeWritten(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	access := e.login(t, admin).AccessToken
	if err := e.db.Migrator().DropTable(&audit.Log{}); err != nil {
		t.Fatal(err)
	}
	if w := e.request(http.MethodPost, "/v1/admin/users/"+target.UUID.String()+"/impersonate", access, ""); w.Code != http.StatusInternalServerError {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var count int64
	if err := e.db.Model(&session.Session{}).Where("impersonator_user_id IS NOT NULL").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("a login-as session exists with no audit record")
	}
}
