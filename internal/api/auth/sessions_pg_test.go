//go:build integration

package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	pdb "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/db"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/pgtest"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// newPGEnv runs the module against the real schema, the advisory-lock recorder and a real
// connection pool, where a race on the rotation is a real race.
func newPGEnv(t *testing.T) *testEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db := pgtest.Open(t)
	if err := pdb.UpMigrations(db, zerolog.Nop()); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.AuthSecurity.PasswordResetCooldown = time.Hour
	mailer := &recordingMailer{}
	d := Deps{
		Cfg:    cfg,
		DB:     db,
		Issuer: platformauth.NewJWTIssuer(testSecret, "iss", "aud", cfg.JWT.TokenExpiration),
		Audit:  auditlog.NewGormRecorder(db, zerolog.Nop()),
		Log:    zerolog.Nop(),
		Mailer: mailer,
		Jobs:   syncJobs{},
	}
	return &testEnv{db: db, router: buildRouter(d), deps: d, mailer: mailer}
}

func TestConcurrentRefreshOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	u := e.addUser(t, entities.RoleUser)
	tokens := e.login(t, u)

	const burst = 16
	codes := make([]int, burst)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i] = e.refresh(t, tokens.RefreshToken).Code
		}()
	}
	close(start)
	wg.Wait()

	wins := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			wins++
		case http.StatusConflict:
		default:
			t.Fatalf("unexpected status in %v", codes)
		}
	}
	if wins != 1 {
		t.Fatalf("%d winners in %v", wins, codes)
	}
	if n := e.countEvents(t, audit.EventRefreshReuse); n != 0 {
		t.Fatalf("a burst was treated as a replay %d times", n)
	}
	var revoked int64
	if err := e.db.Raw(`SELECT count(*) FROM sessions WHERE revoked_at IS NOT NULL`).Scan(&revoked).Error; err != nil {
		t.Fatal(err)
	}
	if revoked != 0 {
		t.Fatal("the burst revoked the session")
	}
	res, err := auditlog.VerifyStored(context.Background(), e.db, nil)
	if err != nil || !res.OK {
		t.Fatalf("audit chain: %+v %v", res, err)
	}
}

func TestOlderGenerationRevokesTheFamilyOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	gen0 := e.login(t, e.addUser(t, entities.RoleUser))
	gen1 := decodeData[AuthResponse](t, e.refresh(t, gen0.RefreshToken)).Tokens
	gen2 := decodeData[AuthResponse](t, e.refresh(t, gen1.RefreshToken)).Tokens

	if w := e.refresh(t, gen1.RefreshToken); w.Code != http.StatusConflict {
		t.Fatalf("N-1 inside the window: %d %s", w.Code, w.Body.String())
	}
	if !e.securedOK(t, gen2.AccessToken) {
		t.Fatal("N-1 inside the window must not revoke")
	}
	if w := e.refresh(t, "a-token-nobody-ever-issued"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown: %d", w.Code)
	}
	if !e.securedOK(t, gen2.AccessToken) {
		t.Fatal("an unknown token must not revoke")
	}
	if w := e.refresh(t, gen0.RefreshToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("N-2: %d %s", w.Code, w.Body.String())
	}
	if e.securedOK(t, gen2.AccessToken) {
		t.Fatal("N-2 must revoke the family")
	}
	if w := e.refresh(t, gen2.RefreshToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("the current token survived: %d", w.Code)
	}
}

func TestReplayAndRevocationOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	u := e.addUser(t, entities.RoleUser)
	first := e.login(t, u)
	other := e.login(t, u)
	second := decodeData[AuthResponse](t, e.refresh(t, first.RefreshToken)).Tokens

	s := e.sessionByRefresh(t, second.RefreshToken)
	if !s.AbsoluteExpiry.After(time.Now()) {
		t.Fatalf("expiry did not round trip: %v", s.AbsoluteExpiry)
	}
	e.ageRotation(t, s.ID)
	if w := e.refresh(t, first.RefreshToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("replay: %d", w.Code)
	}
	if e.securedOK(t, second.AccessToken) {
		t.Fatal("replay must end the family")
	}
	if !e.securedOK(t, other.AccessToken) {
		t.Fatal("replay must leave other families alone")
	}

	third := e.login(t, u)
	if w := e.request(http.MethodDelete, "/v1/auth/sessions", third.AccessToken, ""); w.Code != http.StatusOK {
		t.Fatalf("revoke others: %d %s", w.Code, w.Body.String())
	}
	if e.securedOK(t, other.AccessToken) || !e.securedOK(t, third.AccessToken) {
		t.Fatal("revoke others hit the wrong sessions")
	}
	res, err := auditlog.VerifyStored(context.Background(), e.db, nil)
	if err != nil || !res.OK {
		t.Fatalf("audit chain: %+v %v", res, err)
	}
}
