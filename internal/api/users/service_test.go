package users

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const testSecret = "test-secret-test-secret-test-secret"

type env struct {
	db       *gorm.DB
	router   *gin.Engine
	svc      *Service
	issuer   *platformauth.JWTIssuer
	recorder *auditlog.Recorder
}

func newEnv(t *testing.T) *env {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.Exec(`CREATE TABLE users (
		id integer primary key, created_at datetime, updated_at datetime, deleted_at datetime,
		uuid text, email text, password_hash text, name text, platform_role text, google_id text, avatar_url text,
		totp_secret_enc text, mfa_enrolled_at datetime, mfa_pending_secret_enc text, mfa_pending_at datetime,
		totp_last_step integer)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&audit.Log{}, &session.Session{}); err != nil {
		t.Fatal(err)
	}
	return wire(t, db, auditlog.NewRecorder(repo.NewGormRepo[audit.Log](db), zerolog.Nop()))
}

func wire(t *testing.T, db *gorm.DB, recorder *auditlog.Recorder) *env {
	t.Helper()
	gin.SetMode(gin.TestMode)
	verifier := platformauth.NewJWTVerifier(testSecret, "iss", "aud")
	users := repo.NewGormRepo[user.User](db)
	sessions := repo.NewGormRepo[session.Session](db)
	r := gin.New()
	admin := r.Group("/v1/admin")
	admin.Use(middleware.AdminAuth(verifier, users, sessions, nil, false))
	RegisterRoutes(admin, db, recorder)
	secured := r.Group("/v1")
	secured.Use(middleware.UserAuth(verifier, users, sessions, nil, false))
	secured.GET("/ping", func(c *gin.Context) { c.Status(http.StatusOK) })
	return &env{
		db:       db,
		router:   r,
		svc:      NewService(db, recorder),
		issuer:   platformauth.NewJWTIssuer(testSecret, "iss", "aud", time.Minute),
		recorder: recorder,
	}
}

func (e *env) addUser(t *testing.T, role entities.Role) *user.User {
	t.Helper()
	u := &user.User{UUID: uuid.New(), Email: uuid.NewString() + "@example.com", Name: "n", PlatformRole: role}
	if err := e.db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

// signIn creates a session and returns its access token.
func (e *env) signIn(t *testing.T, u *user.User, impersonator *uint) string {
	t.Helper()
	s := &session.Session{
		UUID: uuid.New(), UserID: u.ID, RefreshTokenHash: uuid.NewString(), LoginMethod: session.MethodPassword,
		ImpersonatorUserID: impersonator, LastUsedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour), AbsoluteExpiry: time.Now().Add(time.Hour),
	}
	if err := e.db.Create(s).Error; err != nil {
		t.Fatal(err)
	}
	p := platformauth.AccessParams{Subject: u.UUID.String(), SID: s.UUID.String()}
	if impersonator != nil {
		p.Impersonator = *impersonator
	}
	tok, err := e.issuer.IssueAccessToken(p)
	if err != nil {
		t.Fatal(err)
	}
	return tok.Token
}

func (e *env) patch(t *testing.T, access, target, role string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(ChangeRoleRequest{Role: role})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/v1/admin/users/"+target+"/role", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if access != "" {
		req.Header.Set("Authorization", "Bearer "+access)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

func (e *env) stillSignedIn(t *testing.T, access string) bool {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/v1/ping", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w.Code == http.StatusOK
}

func (e *env) roleOf(t *testing.T, u *user.User) entities.Role {
	t.Helper()
	var row user.User
	if err := e.db.First(&row, u.ID).Error; err != nil {
		t.Fatal(err)
	}
	return row.PlatformRole
}

func (e *env) events(t *testing.T, event string) []audit.Log {
	t.Helper()
	var rows []audit.Log
	if err := e.db.Where("event = ?", event).Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body apicommon.Response[any]
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return body.Error
}

func TestRoleChangeSignsOutOnlyTheTargetAndIsAudited(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	adminToken := e.signIn(t, admin, nil)
	targetToken := e.signIn(t, target, nil)
	bystander := e.addUser(t, entities.RoleUser)
	bystanderToken := e.signIn(t, bystander, nil)

	w := e.patch(t, adminToken, target.UUID.String(), string(entities.RoleSupport))
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var body apicommon.Response[RoleResponse]
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.PlatformRole != string(entities.RoleSupport) || body.Data.UUID != target.UUID.String() {
		t.Fatalf("%+v", body.Data)
	}
	if got := e.roleOf(t, target); got != entities.RoleSupport {
		t.Fatalf("role = %q", got)
	}
	if e.stillSignedIn(t, targetToken) {
		t.Fatal("the target's sessions must be revoked")
	}
	if !e.stillSignedIn(t, adminToken) || !e.stillSignedIn(t, bystanderToken) {
		t.Fatal("others were signed out")
	}

	rows := e.events(t, audit.EventUserRoleChanged)
	if len(rows) != 1 {
		t.Fatalf("%d audit rows", len(rows))
	}
	row := rows[0]
	if row.ActorUserID == nil || *row.ActorUserID != admin.ID {
		t.Fatalf("actor: %+v", row.ActorUserID)
	}
	for _, want := range []string{target.UUID.String(), `"old_role":"user"`, `"new_role":"support"`} {
		if !strings.Contains(row.Detail, want) {
			t.Fatalf("detail %s lacks %s", row.Detail, want)
		}
	}
}

func TestPromotionTakesEffect(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	if w := e.patch(t, e.signIn(t, admin, nil), target.UUID.String(), string(entities.RoleAdmin)); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	other := e.addUser(t, entities.RoleUser)
	if w := e.patch(t, e.signIn(t, target, nil), other.UUID.String(), string(entities.RoleSupport)); w.Code != http.StatusOK {
		t.Fatalf("a new admin should hold the capability: %d %s", w.Code, w.Body.String())
	}
}

func TestChangeRoleInputs(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	token := e.signIn(t, admin, nil)
	cases := []struct {
		name, target, role string
		want               int
	}{
		{"unknown role", target.UUID.String(), "root", http.StatusBadRequest},
		{"role in the wrong case", target.UUID.String(), "ADMIN", http.StatusBadRequest},
		{"empty role", target.UUID.String(), "", http.StatusBadRequest},
		{"unknown user", uuid.NewString(), string(entities.RoleUser), http.StatusNotFound},
		{"malformed user", "not-a-uuid", string(entities.RoleUser), http.StatusNotFound},
	}
	for _, tc := range cases {
		if w := e.patch(t, token, tc.target, tc.role); w.Code != tc.want {
			t.Errorf("%s: %d %s", tc.name, w.Code, w.Body.String())
		}
	}
	if got := e.roleOf(t, target); got != entities.RoleUser {
		t.Fatalf("role changed to %q", got)
	}
}

func TestOnlyTheCapabilityHolderGetsThrough(t *testing.T) {
	e := newEnv(t)
	target := e.addUser(t, entities.RoleUser)
	for _, role := range []entities.Role{entities.RoleUser, entities.RoleSupport} {
		caller := e.addUser(t, role)
		token := e.signIn(t, caller, nil)
		if w := e.patch(t, token, target.UUID.String(), string(entities.RoleSupport)); w.Code != http.StatusForbidden {
			t.Errorf("%s changing another: %d", role, w.Code)
		}
		// Promoting oneself is the escalation that matters most.
		if w := e.patch(t, token, caller.UUID.String(), string(entities.RoleAdmin)); w.Code != http.StatusForbidden {
			t.Errorf("%s promoting self: %d", role, w.Code)
		}
		if got := e.roleOf(t, caller); got != role {
			t.Errorf("%s became %q", role, got)
		}
	}
	if w := e.patch(t, "", target.UUID.String(), string(entities.RoleSupport)); w.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", w.Code)
	}
	if got := e.roleOf(t, target); got != entities.RoleUser {
		t.Fatalf("role changed to %q", got)
	}
}

// The route gate can be passed by a role that does not hold up: the service decides on the
// row it locks, not the subject the request started with.
func TestServiceDecidesOnTheActorsCurrentRole(t *testing.T) {
	e := newEnv(t)
	demoted, target := e.addUser(t, entities.RoleUser), e.addUser(t, entities.RoleUser)
	stale := authz.Subject{UserID: demoted.ID, Role: entities.RoleAdmin}

	_, err := e.svc.ChangeRole(context.Background(), stale, target.UUID.String(), string(entities.RoleAdmin), "10.0.0.1")
	var apiErr *apierr.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusForbidden {
		t.Fatalf("err = %v", err)
	}
	if got := e.roleOf(t, target); got != entities.RoleUser {
		t.Fatalf("role changed to %q", got)
	}
	rows := e.events(t, audit.EventUserRoleChangeDenied)
	if len(rows) != 1 || !strings.Contains(rows[0].Detail, "actor_lacks_capability") {
		t.Fatalf("%+v", rows)
	}
}

func TestLastAdminCannotBeDemoted(t *testing.T) {
	e := newEnv(t)
	admin := e.addUser(t, entities.RoleAdmin)
	token := e.signIn(t, admin, nil)

	w := e.patch(t, token, admin.UUID.String(), string(entities.RoleUser))
	if w.Code != http.StatusConflict || errorCode(t, w) != "last_admin" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if got := e.roleOf(t, admin); got != entities.RoleAdmin {
		t.Fatalf("role = %q", got)
	}
	if !e.stillSignedIn(t, token) {
		t.Fatal("a refused change must not sign anyone out")
	}
	rows := e.events(t, audit.EventUserRoleChangeDenied)
	if len(rows) != 1 || !strings.Contains(rows[0].Detail, "last_admin") {
		t.Fatalf("%+v", rows)
	}
	if n := len(e.events(t, audit.EventUserRoleChanged)); n != 0 {
		t.Fatalf("%d changed rows", n)
	}
}

func TestAdminCanBeDemotedWhileAnotherRemains(t *testing.T) {
	e := newEnv(t)
	a, b := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleAdmin)
	aToken := e.signIn(t, a, nil)

	if w := e.patch(t, aToken, b.UUID.String(), string(entities.RoleUser)); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if w := e.patch(t, aToken, a.UUID.String(), string(entities.RoleUser)); w.Code != http.StatusConflict {
		t.Fatalf("now the last one: %d %s", w.Code, w.Body.String())
	}
}

// A deleted admin cannot sign in, so it must not count as the admin who remains.
func TestDeletedAdminDoesNotCount(t *testing.T) {
	e := newEnv(t)
	a, gone := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleAdmin)
	if err := e.db.Delete(gone).Error; err != nil {
		t.Fatal(err)
	}
	if w := e.patch(t, e.signIn(t, a, nil), a.UUID.String(), string(entities.RoleUser)); w.Code != http.StatusConflict {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestAdminMaySelfDemoteWhileAnotherRemains(t *testing.T) {
	e := newEnv(t)
	a := e.addUser(t, entities.RoleAdmin)
	e.addUser(t, entities.RoleAdmin)
	token := e.signIn(t, a, nil)
	if w := e.patch(t, token, a.UUID.String(), string(entities.RoleUser)); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if e.stillSignedIn(t, token) {
		t.Fatal("the change revokes the target's sessions, here the caller's own")
	}
}

func TestSameRoleChangesNothing(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleSupport)
	targetToken := e.signIn(t, target, nil)
	if w := e.patch(t, e.signIn(t, admin, nil), target.UUID.String(), string(entities.RoleSupport)); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if !e.stillSignedIn(t, targetToken) {
		t.Fatal("nothing changed, so nobody should be signed out")
	}
	if n := len(e.events(t, audit.EventUserRoleChanged)); n != 0 {
		t.Fatalf("%d audit rows for no change", n)
	}
	// The only admin keeping their role is not a demotion.
	if w := e.patch(t, e.signIn(t, admin, nil), admin.UUID.String(), string(entities.RoleAdmin)); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestLoginAsSessionCannotChangeRoles(t *testing.T) {
	e := newEnv(t)
	admin, promoted, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	// A login-as session holding an admin role: only the impersonation bar stands in the way.
	impersonator := admin.ID
	w := e.patch(t, e.signIn(t, promoted, &impersonator), target.UUID.String(), string(entities.RoleAdmin))
	if w.Code != http.StatusForbidden {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if got := e.roleOf(t, target); got != entities.RoleUser {
		t.Fatalf("role changed to %q", got)
	}
}

func TestDemotingAnAdminEndsTheirLoginAsSessions(t *testing.T) {
	e := newEnv(t)
	a, b, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	impersonator := b.ID
	loginAs := e.signIn(t, target, &impersonator)
	if !e.stillSignedIn(t, loginAs) {
		t.Fatal("setup: the login-as session should work")
	}
	if w := e.patch(t, e.signIn(t, a, nil), b.UUID.String(), string(entities.RoleUser)); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if e.stillSignedIn(t, loginAs) {
		t.Fatal("a demoted admin kept acting as someone else")
	}
}

func TestChangeRollsBackIfTheAuditRowCannotBeWritten(t *testing.T) {
	e := newEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	adminToken, targetToken := e.signIn(t, admin, nil), e.signIn(t, target, nil)
	if err := e.db.Migrator().DropTable(&audit.Log{}); err != nil {
		t.Fatal(err)
	}
	if w := e.patch(t, adminToken, target.UUID.String(), string(entities.RoleAdmin)); w.Code != http.StatusInternalServerError {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if got := e.roleOf(t, target); got != entities.RoleUser {
		t.Fatalf("the role changed with no audit record: %q", got)
	}
	if !e.stillSignedIn(t, targetToken) {
		t.Fatal("the revocation should have rolled back too")
	}
}
