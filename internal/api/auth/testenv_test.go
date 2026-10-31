package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/loginfailure"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/mfa"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/passwordhistory"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/passwordreset"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/worker"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	testSecret    = "test-secret-test-secret-test-secret"
	testPassword  = "correct-horse-battery"
	raceWindow    = 30 * time.Second
	lockoutWindow = 15 * time.Minute

	testMFAKey           = "test-mfa-key-test-mfa-key-test-mfa-key"
	testMFAMaxAttempts   = 5
	testLockoutThreshold = 3
	backupCodeTestCount  = 4
	uuidMissing          = "00000000-0000-4000-8000-000000000000"
)

type testEnv struct {
	db     *gorm.DB
	router *gin.Engine
	deps   Deps
	mailer *recordingMailer
}

type sentMail struct{ to, subject, body string }

// recordingMailer keeps what was sent.
type recordingMailer struct {
	mu   sync.Mutex
	sent []sentMail
}

func (m *recordingMailer) Send(_ context.Context, to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, sentMail{to, subject, body})
	return nil
}

func (m *recordingMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func (m *recordingMailer) last(t *testing.T) sentMail {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		t.Fatal("no email was sent")
	}
	return m.sent[len(m.sent)-1]
}

// syncJobs runs a job before Enqueue returns, so tests can assert on its effects. The
// test that proves the handler does not wait uses a real worker instead.
type syncJobs struct{}

func (syncJobs) Enqueue(job worker.Job) error {
	_ = job(context.Background())
	return nil
}

func testConfig() config.Config {
	return config.Config{
		Env: "test",
		JWT: config.JWTConfig{
			SecretKey: testSecret, TokenIssuer: "iss", TokenAudience: "aud",
			TokenExpiration: 15 * time.Minute, RefreshTokenExpiry: time.Hour,
		},
		AuthSecurity: config.AuthSecurityConfig{
			SessionAbsoluteTTL:   24 * time.Hour,
			RefreshRaceWindow:    raceWindow,
			LockoutThreshold:     testLockoutThreshold,
			LockoutWindow:        lockoutWindow,
			PasswordResetTTL:     time.Hour,
			PasswordHistoryCount: 2,
			PasswordResetURL:     "https://app.example.com/reset-password",
		},
		MFA: config.MFAConfig{
			EncryptionKey:   testMFAKey,
			Issuer:          "test",
			EnrollTTL:       15 * time.Minute,
			ChallengeTTL:    5 * time.Minute,
			MaxAttempts:     testMFAMaxAttempts,
			BackupCodeCount: backupCodeTestCount,
		},
	}
}

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	// One connection, because each new one to file::memory: is a different empty database.
	// It also makes a query that escapes an open transaction hang the test instead of
	// passing unnoticed.
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	// By hand, because uuid_generate_v4() and citext do not exist on sqlite.
	if err := db.Exec(`CREATE TABLE users (
		id integer primary key, created_at datetime, updated_at datetime, deleted_at datetime,
		uuid text, email text collate nocase unique, password_hash text, name text,
		platform_role text default 'user', google_id text, avatar_url text,
		totp_secret_enc text, mfa_enrolled_at datetime, mfa_pending_secret_enc text, mfa_pending_at datetime,
		totp_last_step integer)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(
		&audit.Log{}, &session.Session{}, &session.RetiredRefreshToken{},
		&passwordreset.Token{}, &passwordhistory.Entry{}, &loginfailure.Failure{},
		&mfa.BackupCode{}, &mfa.Challenge{},
	); err != nil {
		t.Fatal(err)
	}
	return db
}

func newEnv(t *testing.T, edit ...func(*Deps)) *testEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := openTestDB(t)
	cfg := testConfig()
	mailer := &recordingMailer{}
	d := Deps{
		Cfg:    cfg,
		DB:     db,
		Issuer: platformauth.NewJWTIssuer(testSecret, "iss", "aud", cfg.JWT.TokenExpiration),
		Audit:  auditlog.NewRecorder(repo.NewGormRepo[audit.Log](db), zerolog.Nop()),
		Log:    zerolog.Nop(),
		Mailer: mailer,
		Jobs:   syncJobs{},
	}
	for _, f := range edit {
		f(&d)
	}
	return &testEnv{db: db, router: buildRouter(d), deps: d, mailer: mailer}
}

// buildRouter wires the module behind the real UserAuth, so these tests exercise what a
// client gets rather than a stubbed actor. Redis is nil throughout: everything here must
// work without it.
func buildRouter(d Deps) *gin.Engine {
	verifier := platformauth.NewJWTVerifier(testSecret, "iss", "aud")
	users := repo.NewGormRepo[user.User](d.DB)
	sessions := repo.NewGormRepo[session.Session](d.DB)
	r := gin.New()
	v1 := r.Group("/v1")
	secured := v1.Group("")
	secured.Use(middleware.UserAuth(verifier, users, sessions, nil, false))
	admin := v1.Group("/admin")
	admin.Use(middleware.AdminAuth(verifier, users, sessions, nil, false))
	RegisterRoutes(v1, secured, admin, d)
	return r
}

func (e *testEnv) addUser(t *testing.T, role entities.Role) *user.User {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := &user.User{
		UUID: uuid.New(), Email: uuid.NewString() + "@example.com", Name: "Test User",
		PasswordHash: string(hash), PlatformRole: role,
	}
	if err := e.db.Create(u).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

func (e *testEnv) request(method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-agent")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

func decodeData[T any](t *testing.T, w *httptest.ResponseRecorder) *T {
	t.Helper()
	var body apicommon.Response[T]
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	if body.Data == nil {
		t.Fatalf("no data in %d %s", w.Code, w.Body.String())
	}
	return body.Data
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body apicommon.Response[any]
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return body.Error
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// login signs in and returns the tokens.
func (e *testEnv) login(t *testing.T, u *user.User) TokenPairResponse {
	t.Helper()
	w := e.request(http.MethodPost, "/v1/auth/login", "", mustJSON(t, LoginRequest{Email: u.Email, Password: testPassword}))
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	return decodeData[AuthResponse](t, w).Tokens
}

func (e *testEnv) refresh(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	return e.request(http.MethodPost, "/v1/auth/refresh", "", mustJSON(t, RefreshRequest{RefreshToken: token}))
}

// securedOK reports whether an access token gets through UserAuth.
func (e *testEnv) securedOK(t *testing.T, access string) bool {
	t.Helper()
	switch w := e.request(http.MethodGet, "/v1/auth/permissions", access, ""); w.Code {
	case http.StatusOK:
		return true
	case http.StatusUnauthorized:
		return false
	default:
		t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
		return false
	}
}

func (e *testEnv) sessionByRefresh(t *testing.T, token string) *session.Session {
	t.Helper()
	var s session.Session
	if err := e.db.Where("refresh_token_hash = ?", platformauth.HashToken(token)).First(&s).Error; err != nil {
		t.Fatal(err)
	}
	return &s
}

func (e *testEnv) auditEvents(t *testing.T) []audit.Log {
	t.Helper()
	var rows []audit.Log
	if err := e.db.Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func (e *testEnv) countEvents(t *testing.T, event string) int {
	t.Helper()
	n := 0
	for _, r := range e.auditEvents(t) {
		if r.Event == event {
			n++
		}
	}
	return n
}

// ageRotation moves a session's last rotation past the race window.
func (e *testEnv) ageRotation(t *testing.T, id uint) {
	t.Helper()
	if err := e.db.Model(&session.Session{}).Where("id = ?", id).
		Update("rotated_at", time.Now().Add(-2*raceWindow)).Error; err != nil {
		t.Fatal(err)
	}
}
