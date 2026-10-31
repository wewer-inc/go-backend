package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
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
		uuid text, email text, password_hash text, name text, platform_role text, google_id text, avatar_url text)`).Error; err != nil {
		t.Fatal(err)
	}
	return &authEnv{
		db:       db,
		issuer:   auth.NewJWTIssuer(testSecret, "iss", "aud", time.Minute, time.Hour),
		verifier: auth.NewJWTVerifier(testSecret, "iss", "aud"),
		users:    repo.NewGormRepo[user.User](db),
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

func (e *authEnv) token(t *testing.T, u *user.User) string {
	t.Helper()
	tok, err := e.issuer.IssueAccessToken(u.UUID.String())
	if err != nil {
		t.Fatal(err)
	}
	return tok.Token
}

// AdminAuth once ran the rest of the chain inside its authentication step and only then
// checked the role, so a non-admin's request reached the handler before being refused.
func TestAdminAuthChecksTheRoleBeforeRunningTheHandler(t *testing.T) {
	e := newAuthEnv(t)
	ran := false
	r := gin.New()
	r.GET("/x", AdminAuth(e.verifier, e.users, nil, false), func(c *gin.Context) {
		ran = true
		c.Status(http.StatusOK)
	})

	call := func(u *user.User) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+e.token(t, u))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	if w := call(e.addUser(t, entities.RoleUser)); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin: %d", w.Code)
	}
	if ran {
		t.Fatal("the handler ran for a non-admin")
	}
	if w := call(e.addUser(t, entities.RoleAdmin)); w.Code != http.StatusOK || !ran {
		t.Fatalf("admin: %d ran=%v", w.Code, ran)
	}
}
