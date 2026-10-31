package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const testSecret = "test-secret-test-secret-test-secret"

type authEnv struct {
	db       *gorm.DB
	issuer   *auth.JWTIssuer
	verifier *auth.JWTVerifier
	users    repo.Repo[user.User]
	sessions repo.Repo[session.Session]
}

func newAuthEnv(t *testing.T) *authEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.Exec(`CREATE TABLE users (
		id integer primary key, created_at datetime, updated_at datetime, deleted_at datetime,
		uuid text, email text, password_hash text, name text, platform_role text, google_id text, avatar_url text,
		totp_secret_enc text, mfa_enrolled_at datetime, mfa_pending_secret_enc text, mfa_pending_at datetime)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&session.Session{}); err != nil {
		t.Fatal(err)
	}
	return &authEnv{
		db:       db,
		issuer:   auth.NewJWTIssuer(testSecret, "iss", "aud", time.Minute),
		verifier: auth.NewJWTVerifier(testSecret, "iss", "aud"),
		users:    repo.NewGormRepo[user.User](db),
		sessions: repo.NewGormRepo[session.Session](db),
	}
}

func (e *authEnv) addUser(t *testing.T, role entities.Role) *user.User {
	t.Helper()
	u := &user.User{UUID: uuid.New(), Email: uuid.NewString() + "@example.com", Name: "n", PlatformRole: role}
	if err := e.db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *authEnv) addSession(t *testing.T, u *user.User) *session.Session {
	t.Helper()
	s := &session.Session{
		UUID: uuid.New(), UserID: u.ID, RefreshTokenHash: uuid.NewString(), LoginMethod: session.MethodPassword,
		LastUsedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), AbsoluteExpiry: time.Now().Add(time.Hour),
	}
	if err := e.db.Create(s).Error; err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *authEnv) tokenFor(t *testing.T, u *user.User, sid string) string {
	t.Helper()
	tok, err := e.issuer.IssueAccessToken(auth.AccessParams{Subject: u.UUID.String(), SID: sid})
	if err != nil {
		t.Fatal(err)
	}
	return tok.Token
}

func call(r http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func (e *authEnv) userAuthRouter() *gin.Engine {
	r := gin.New()
	r.GET("/x", UserAuth(e.verifier, e.users, e.sessions, nil, false), func(c *gin.Context) { c.Status(http.StatusOK) })
	return r
}

// AdminAuth once ran the rest of the chain inside its authentication step and only then
// checked the role, so a non-admin's request reached the handler before being refused.
func TestAdminAuthChecksTheRoleBeforeRunningTheHandler(t *testing.T) {
	e := newAuthEnv(t)
	ran := false
	r := gin.New()
	r.GET("/x", AdminAuth(e.verifier, e.users, e.sessions, nil, false), func(c *gin.Context) {
		ran = true
		c.Status(http.StatusOK)
	})

	plain := e.addUser(t, entities.RoleUser)
	if w := call(r, e.tokenFor(t, plain, e.addSession(t, plain).UUID.String())); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin: %d", w.Code)
	}
	if ran {
		t.Fatal("the handler ran for a non-admin")
	}
	admin := e.addUser(t, entities.RoleAdmin)
	if w := call(r, e.tokenFor(t, admin, e.addSession(t, admin).UUID.String())); w.Code != http.StatusOK || !ran {
		t.Fatalf("admin: %d ran=%v", w.Code, ran)
	}
}

func TestUserAuthSessionChecks(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	cases := []struct {
		name   string
		mutate func(t *testing.T, e *authEnv, s *session.Session)
		want   int
	}{
		{"live session", func(*testing.T, *authEnv, *session.Session) {}, http.StatusOK},
		{"revoked session", func(t *testing.T, e *authEnv, s *session.Session) {
			if err := e.db.Model(s).Update("revoked_at", past).Error; err != nil {
				t.Fatal(err)
			}
		}, http.StatusUnauthorized},
		{"past its absolute expiry", func(t *testing.T, e *authEnv, s *session.Session) {
			if err := e.db.Model(s).Update("absolute_expiry", past).Error; err != nil {
				t.Fatal(err)
			}
		}, http.StatusUnauthorized},
		{"session row gone", func(t *testing.T, e *authEnv, s *session.Session) {
			if err := e.db.Delete(s).Error; err != nil {
				t.Fatal(err)
			}
		}, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newAuthEnv(t)
			u := e.addUser(t, entities.RoleUser)
			s := e.addSession(t, u)
			tc.mutate(t, e, s)
			if w := call(e.userAuthRouter(), e.tokenFor(t, u, s.UUID.String())); w.Code != tc.want {
				t.Fatalf("status %d", w.Code)
			}
		})
	}
}

func TestUserAuthRefusesATokenWithoutASession(t *testing.T) {
	e := newAuthEnv(t)
	u := e.addUser(t, entities.RoleUser)
	if w := call(e.userAuthRouter(), e.tokenFor(t, u, "")); w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestUserAuthRefusesAnotherUsersSession(t *testing.T) {
	e := newAuthEnv(t)
	alice, bob := e.addUser(t, entities.RoleUser), e.addUser(t, entities.RoleUser)
	if w := call(e.userAuthRouter(), e.tokenFor(t, alice, e.addSession(t, bob).UUID.String())); w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

// A refresh JWT signed before refresh tokens became opaque must stay useless as a bearer
// token, even one naming a live session.
func TestUserAuthRefusesARefreshJWT(t *testing.T) {
	e := newAuthEnv(t)
	u := e.addUser(t, entities.RoleUser)
	s := e.addSession(t, u)
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": u.UUID.String(), "sid": s.UUID.String(), "token_use": string(auth.UseRefresh),
		"iss": "iss", "aud": "aud", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	if w := call(e.userAuthRouter(), raw); w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
}

func TestUserAuthAnswers503WhenSessionsCannotBeRead(t *testing.T) {
	e := newAuthEnv(t)
	u := e.addUser(t, entities.RoleUser)
	s := e.addSession(t, u)
	if err := e.db.Migrator().DropTable(&session.Session{}); err != nil {
		t.Fatal(err)
	}
	if w := call(e.userAuthRouter(), e.tokenFor(t, u, s.UUID.String())); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", w.Code)
	}
}

func TestUserAuthSetsTheImpersonatorFromTheToken(t *testing.T) {
	e := newAuthEnv(t)
	u := e.addUser(t, entities.RoleUser)
	s := e.addSession(t, u)
	imp := uint(42)
	if err := e.db.Model(s).Update("impersonator_user_id", &imp).Error; err != nil {
		t.Fatal(err)
	}
	tok, err := e.issuer.IssueAccessToken(auth.AccessParams{Subject: u.UUID.String(), SID: s.UUID.String(), Impersonator: imp})
	if err != nil {
		t.Fatal(err)
	}
	var got authz.Subject
	r := gin.New()
	r.GET("/x", UserAuth(e.verifier, e.users, e.sessions, nil, false), func(c *gin.Context) {
		got, _ = GetActorSubject(c)
		c.Status(http.StatusOK)
	})
	if w := call(r, tok.Token); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if got.Impersonator == nil || *got.Impersonator != imp || got.UserID != u.ID {
		t.Fatalf("subject = %+v", got)
	}
}

func TestOrdinarySessionHasNoImpersonator(t *testing.T) {
	e := newAuthEnv(t)
	u := e.addUser(t, entities.RoleUser)
	var got authz.Subject
	r := gin.New()
	r.GET("/x", UserAuth(e.verifier, e.users, e.sessions, nil, false), func(c *gin.Context) {
		got, _ = GetActorSubject(c)
		c.Status(http.StatusOK)
	})
	if w := call(r, e.tokenFor(t, u, e.addSession(t, u).UUID.String())); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if got.Impersonator != nil {
		t.Fatalf("subject = %+v", got)
	}
}

// The token and the session must agree. Otherwise a token without act could drop the
// label from a login-as session, or one with act could pin blame on someone else.
func TestUserAuthRefusesAMismatchedImpersonator(t *testing.T) {
	e := newAuthEnv(t)
	u := e.addUser(t, entities.RoleUser)
	ordinary := e.addSession(t, u)
	loginAs := e.addSession(t, u)
	imp := uint(42)
	if err := e.db.Model(loginAs).Update("impersonator_user_id", &imp).Error; err != nil {
		t.Fatal(err)
	}
	cases := map[string]auth.AccessParams{
		"act on an ordinary session":      {Subject: u.UUID.String(), SID: ordinary.UUID.String(), Impersonator: 42},
		"no act on a login-as session":    {Subject: u.UUID.String(), SID: loginAs.UUID.String()},
		"wrong act on a login-as session": {Subject: u.UUID.String(), SID: loginAs.UUID.String(), Impersonator: 43},
	}
	for name, p := range cases {
		tok, err := e.issuer.IssueAccessToken(p)
		if err != nil {
			t.Fatal(err)
		}
		if w := call(e.userAuthRouter(), tok.Token); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
}

// The role must come from the row, so a demotion applies to the next request.
func TestSubjectRoleComesFromTheDatabaseNotTheToken(t *testing.T) {
	e := newAuthEnv(t)
	u := e.addUser(t, entities.RoleAdmin)
	token := e.tokenFor(t, u, e.addSession(t, u).UUID.String())
	var got entities.Role
	r := gin.New()
	r.GET("/x", UserAuth(e.verifier, e.users, e.sessions, nil, false), func(c *gin.Context) {
		s, _ := GetActorSubject(c)
		got = s.Role
		c.Status(http.StatusOK)
	})
	if err := e.db.Model(u).Update("platform_role", entities.RoleUser).Error; err != nil {
		t.Fatal(err)
	}
	if w := call(r, token); w.Code != http.StatusOK || got != entities.RoleUser {
		t.Fatalf("status %d role %q", w.Code, got)
	}
}
