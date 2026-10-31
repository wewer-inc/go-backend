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

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"golang.org/x/oauth2"
)

func TestRegisterAndLoginStartASessionStoringOnlyTheHash(t *testing.T) {
	e := newEnv(t)
	w := e.request(http.MethodPost, "/v1/auth/register", "", mustJSON(t, RegisterRequest{
		Name: "New", Email: "new@example.com", Password: testPassword,
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	tokens := decodeData[AuthResponse](t, w).Tokens

	var s session.Session
	if err := e.db.First(&s).Error; err != nil {
		t.Fatal(err)
	}
	if s.RefreshTokenHash != platformauth.HashToken(tokens.RefreshToken) || s.RefreshTokenHash == tokens.RefreshToken {
		t.Fatal("the row must hold the token's hash and never the token")
	}
	if strings.Count(tokens.RefreshToken, ".") == 2 {
		t.Fatal("refresh token should be opaque, not a JWT")
	}
	if !e.securedOK(t, tokens.AccessToken) {
		t.Fatal("access token refused")
	}
	claims, err := platformauth.NewJWTVerifier(testSecret, "iss", "aud").Verify(tokens.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if claims.SID != s.UUID.String() {
		t.Fatalf("sid = %q, want %q", claims.SID, s.UUID)
	}
}

func TestLoginRefusesWrongCredentialsAlike(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	wrong := e.request(http.MethodPost, "/v1/auth/login", "", mustJSON(t, LoginRequest{Email: u.Email, Password: "not-the-password"}))
	unknown := e.request(http.MethodPost, "/v1/auth/login", "", mustJSON(t, LoginRequest{Email: "nobody@example.com", Password: "not-the-password"}))
	if wrong.Code != http.StatusUnauthorized || unknown.Code != http.StatusUnauthorized || wrong.Body.String() != unknown.Body.String() {
		t.Fatalf("wrong %d %s, unknown %d %s", wrong.Code, wrong.Body, unknown.Code, unknown.Body)
	}
	if n := e.countEvents(t, audit.EventLoginFailure); n != 2 {
		t.Fatalf("%d failure events", n)
	}
}

func TestRefreshRotatesInPlace(t *testing.T) {
	e := newEnv(t)
	first := e.login(t, e.addUser(t, entities.RoleUser))

	w := e.refresh(t, first.RefreshToken)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", w.Code, w.Body.String())
	}
	second := decodeData[AuthResponse](t, w).Tokens
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("token was not rotated")
	}

	var count int64
	if err := e.db.Model(&session.Session{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("%d rows; a token family is one row", count)
	}
	s := e.sessionByRefresh(t, second.RefreshToken)
	if s.PrevRefreshTokenHash != platformauth.HashToken(first.RefreshToken) || s.RotatedAt == nil {
		t.Fatalf("previous generation not tracked: %+v", s)
	}
	if !e.securedOK(t, second.AccessToken) {
		t.Fatal("new access token refused")
	}
}

func TestReplayedTokenRevokesTheFamily(t *testing.T) {
	e := newEnv(t)
	first := e.login(t, e.addUser(t, entities.RoleUser))
	second := decodeData[AuthResponse](t, e.refresh(t, first.RefreshToken)).Tokens
	e.ageRotation(t, e.sessionByRefresh(t, second.RefreshToken).ID)

	w := e.refresh(t, first.RefreshToken)
	if w.Code != http.StatusUnauthorized || errorCode(t, w) != "session_expired" {
		t.Fatalf("replay: %d %s", w.Code, w.Body.String())
	}
	if e.sessionByRefresh(t, second.RefreshToken).RevokedAt == nil {
		t.Fatal("replay must revoke the family")
	}
	if w := e.refresh(t, second.RefreshToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("the current token must die with the family: %d", w.Code)
	}
	if e.securedOK(t, second.AccessToken) {
		t.Fatal("the access token must die with the family")
	}
	if n := e.countEvents(t, audit.EventRefreshReuse); n != 1 {
		t.Fatalf("%d reuse events", n)
	}
}

// Without rotated_at nothing can show the replay was a race, so it counts as token reuse.
func TestReplayWithNoRotationTimeRevokes(t *testing.T) {
	e := newEnv(t)
	first := e.login(t, e.addUser(t, entities.RoleUser))
	second := decodeData[AuthResponse](t, e.refresh(t, first.RefreshToken)).Tokens
	s := e.sessionByRefresh(t, second.RefreshToken)
	if err := e.db.Model(s).Update("rotated_at", nil).Error; err != nil {
		t.Fatal(err)
	}
	if w := e.refresh(t, first.RefreshToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
	if e.sessionByRefresh(t, second.RefreshToken).RevokedAt == nil {
		t.Fatal("expected revocation")
	}
}

func TestReplayInsideTheRaceWindowKeepsTheSession(t *testing.T) {
	e := newEnv(t)
	first := e.login(t, e.addUser(t, entities.RoleUser))
	second := decodeData[AuthResponse](t, e.refresh(t, first.RefreshToken)).Tokens

	w := e.refresh(t, first.RefreshToken)
	if w.Code != http.StatusConflict || errorCode(t, w) != codeRefreshRetry {
		t.Fatalf("loser: %d %s", w.Code, w.Body.String())
	}
	if e.sessionByRefresh(t, second.RefreshToken).RevokedAt != nil {
		t.Fatal("a concurrent refresh must not sign the user out")
	}
	if !e.securedOK(t, second.AccessToken) {
		t.Fatal("the winner's access token must keep working")
	}
	if w := e.refresh(t, second.RefreshToken); w.Code != http.StatusOK {
		t.Fatalf("the winner's refresh token must keep working: %d", w.Code)
	}
	if n := e.countEvents(t, audit.EventRefreshRace); n != 1 {
		t.Fatalf("%d race events", n)
	}
}

func TestConcurrentRefreshesLeaveExactlyOneWinnerAndALiveSession(t *testing.T) {
	e := newEnv(t)
	first := e.login(t, e.addUser(t, entities.RoleUser))

	const burst = 12
	codes := make([]int, burst)
	bodies := make([]string, burst)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			w := e.refresh(t, first.RefreshToken)
			codes[i], bodies[i] = w.Code, w.Body.String()
		}()
	}
	close(start)
	wg.Wait()

	var winner string
	wins := 0
	for i, code := range codes {
		switch code {
		case http.StatusOK:
			wins++
			var body struct {
				Data AuthResponse `json:"data"`
			}
			if err := json.Unmarshal([]byte(bodies[i]), &body); err != nil {
				t.Fatal(err)
			}
			winner = body.Data.Tokens.RefreshToken
		case http.StatusConflict:
		default:
			t.Fatalf("unexpected %d: %s", code, bodies[i])
		}
	}
	if wins != 1 {
		t.Fatalf("%d winners in %v", wins, codes)
	}
	if w := e.refresh(t, winner); w.Code != http.StatusOK {
		t.Fatalf("the session did not survive the burst: %d %s", w.Code, w.Body.String())
	}
}

func TestRefreshNeverExtendsTheAbsoluteExpiry(t *testing.T) {
	e := newEnv(t)
	first := e.login(t, e.addUser(t, entities.RoleUser))
	s := e.sessionByRefresh(t, first.RefreshToken)
	soon := time.Now().Add(time.Minute).UTC()
	if err := e.db.Model(s).Update("absolute_expiry", soon).Error; err != nil {
		t.Fatal(err)
	}
	second := decodeData[AuthResponse](t, e.refresh(t, first.RefreshToken)).Tokens
	after := e.sessionByRefresh(t, second.RefreshToken)
	if !after.AbsoluteExpiry.Equal(soon) {
		t.Fatalf("absolute expiry moved: %v", after.AbsoluteExpiry)
	}
	if after.ExpiresAt.After(soon) {
		t.Fatalf("refresh expiry %v passes the cap %v", after.ExpiresAt, soon)
	}
}

func TestRefreshRefusals(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	cases := map[string]string{
		"revoked":              "revoked_at",
		"past refresh expiry":  "expires_at",
		"past absolute expiry": "absolute_expiry",
	}
	for name, col := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			tokens := e.login(t, e.addUser(t, entities.RoleUser))
			if err := e.db.Model(e.sessionByRefresh(t, tokens.RefreshToken)).Update(col, past).Error; err != nil {
				t.Fatal(err)
			}
			if w := e.refresh(t, tokens.RefreshToken); w.Code != http.StatusUnauthorized {
				t.Fatalf("status %d", w.Code)
			}
		})
	}
	t.Run("unknown token touches nothing", func(t *testing.T) {
		e := newEnv(t)
		tokens := e.login(t, e.addUser(t, entities.RoleUser))
		if w := e.refresh(t, "not-a-token"); w.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", w.Code)
		}
		if e.sessionByRefresh(t, tokens.RefreshToken).RevokedAt != nil {
			t.Fatal("an unknown token must not affect any session")
		}
	})
	t.Run("an access token is not a refresh token", func(t *testing.T) {
		e := newEnv(t)
		tokens := e.login(t, e.addUser(t, entities.RoleUser))
		if w := e.refresh(t, tokens.AccessToken); w.Code != http.StatusUnauthorized {
			t.Fatalf("status %d", w.Code)
		}
	})
}

func TestRefreshRefusesAnImpersonatedSessionAndRevokesIt(t *testing.T) {
	e := newEnv(t)
	tokens := e.login(t, e.addUser(t, entities.RoleUser))
	s := e.sessionByRefresh(t, tokens.RefreshToken)
	imp := uint(99)
	if err := e.db.Model(s).Update("impersonator_user_id", &imp).Error; err != nil {
		t.Fatal(err)
	}
	if w := e.refresh(t, tokens.RefreshToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
	if e.sessionByRefresh(t, tokens.RefreshToken).RevokedAt == nil {
		t.Fatal("expected revocation")
	}
}

func TestLogoutEndsTheSession(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	here, there := e.login(t, u), e.login(t, u)

	if w := e.request(http.MethodPost, "/v1/auth/logout", here.AccessToken, ""); w.Code != http.StatusOK {
		t.Fatalf("logout: %d %s", w.Code, w.Body.String())
	}
	if e.securedOK(t, here.AccessToken) {
		t.Fatal("a logged-out access token must be refused, with or without Redis")
	}
	if w := e.refresh(t, here.RefreshToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("a logged-out refresh token must be refused: %d", w.Code)
	}
	if !e.securedOK(t, there.AccessToken) {
		t.Fatal("logging out one device must leave the other alone")
	}
	if n := e.countEvents(t, audit.EventLogout); n != 1 {
		t.Fatalf("%d logout events", n)
	}
}

func TestLogoutCannotTouchAnotherUsersSession(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.login(t, e.addUser(t, entities.RoleUser)), e.login(t, e.addUser(t, entities.RoleUser))

	w := e.request(http.MethodPost, "/v1/auth/logout", alice.AccessToken, mustJSON(t, LogoutRequest{RefreshToken: bob.RefreshToken}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d", w.Code)
	}
	if !e.securedOK(t, bob.AccessToken) {
		t.Fatal("bob was signed out")
	}
	if !e.securedOK(t, alice.AccessToken) {
		t.Fatal("a refused logout must not sign the caller out")
	}
}

func TestLogoutRevokesASuppliedSessionOfTheSameUser(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	here, there := e.login(t, u), e.login(t, u)
	if w := e.request(http.MethodPost, "/v1/auth/logout", here.AccessToken, mustJSON(t, LogoutRequest{RefreshToken: there.RefreshToken})); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if e.securedOK(t, there.AccessToken) {
		t.Fatal("the supplied session should have ended too")
	}
}

func TestSessionListMarksCurrentAndHidesSecrets(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	here, there := e.login(t, u), e.login(t, u)
	e.login(t, e.addUser(t, entities.RoleUser)) // another user's session must not appear

	gone := e.login(t, u)
	if w := e.request(http.MethodPost, "/v1/auth/logout", gone.AccessToken, ""); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}

	w := e.request(http.MethodGet, "/v1/auth/sessions", here.AccessToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	for _, secret := range []string{here.RefreshToken, there.RefreshToken, platformauth.HashToken(here.RefreshToken)} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("the list must not expose tokens or hashes")
		}
	}
	views := *decodeData[[]SessionView](t, w)
	if len(views) != 2 {
		t.Fatalf("%d sessions: %+v", len(views), views)
	}
	current := 0
	for _, v := range views {
		if v.Current {
			current++
			if v.UUID != e.sessionByRefresh(t, here.RefreshToken).UUID.String() {
				t.Fatal("wrong session marked current")
			}
		}
		if v.UserAgent != "test-agent" || v.LoginMethod != "password" {
			t.Fatalf("view: %+v", v)
		}
	}
	if current != 1 {
		t.Fatalf("%d current", current)
	}
}

func TestRevokeOneSession(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	here, there := e.login(t, u), e.login(t, u)
	thereSess := e.sessionByRefresh(t, there.RefreshToken)

	if w := e.request(http.MethodDelete, "/v1/auth/sessions/"+thereSess.UUID.String(), here.AccessToken, ""); w.Code != http.StatusOK {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	if e.securedOK(t, there.AccessToken) {
		t.Fatal("revoked session still works")
	}
	if !e.securedOK(t, here.AccessToken) {
		t.Fatal("the caller's own session should survive")
	}
}

func TestRevokeSessionCannotReachAnotherUser(t *testing.T) {
	e := newEnv(t)
	alice, bob := e.login(t, e.addUser(t, entities.RoleUser)), e.login(t, e.addUser(t, entities.RoleUser))
	bobSess := e.sessionByRefresh(t, bob.RefreshToken)

	w := e.request(http.MethodDelete, "/v1/auth/sessions/"+bobSess.UUID.String(), alice.AccessToken, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("another user's session must read as missing: %d", w.Code)
	}
	if !e.securedOK(t, bob.AccessToken) {
		t.Fatal("bob was signed out")
	}
	if w := e.request(http.MethodDelete, "/v1/auth/sessions/not-a-uuid", alice.AccessToken, ""); w.Code != http.StatusNotFound {
		t.Fatalf("malformed id: %d", w.Code)
	}
}

func TestRevokeAllButCurrent(t *testing.T) {
	e := newEnv(t)
	u := e.addUser(t, entities.RoleUser)
	here, a, b := e.login(t, u), e.login(t, u), e.login(t, u)
	bystander := e.login(t, e.addUser(t, entities.RoleUser))

	if w := e.request(http.MethodDelete, "/v1/auth/sessions", here.AccessToken, ""); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if !e.securedOK(t, here.AccessToken) {
		t.Fatal("the current session must survive")
	}
	for _, other := range []TokenPairResponse{a, b} {
		if e.securedOK(t, other.AccessToken) {
			t.Fatal("another session survived")
		}
	}
	if !e.securedOK(t, bystander.AccessToken) {
		t.Fatal("another user was signed out")
	}
}

func TestAuditRowsCarryNoTokens(t *testing.T) {
	e := newEnv(t)
	first := e.login(t, e.addUser(t, entities.RoleUser))
	second := decodeData[AuthResponse](t, e.refresh(t, first.RefreshToken)).Tokens
	for _, row := range e.auditEvents(t) {
		for _, secret := range []string{first.RefreshToken, second.RefreshToken, second.AccessToken, testPassword} {
			if strings.Contains(row.Detail, secret) {
				t.Fatalf("%s carries a secret: %s", row.Event, row.Detail)
			}
		}
	}
}

func TestGoogleLoginIssuesASession(t *testing.T) {
	e := newEnv(t)
	svc := NewService(e.deps)

	oauthServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"google-token","token_type":"bearer"}`))
	}))
	defer oauthServer.Close()
	svc.googleOAuth = &oauth2.Config{ClientID: "id", Endpoint: oauth2.Endpoint{TokenURL: oauthServer.URL}}
	svc.fetchGoogleUser = func(context.Context, *http.Client) (*googleUserInfo, error) {
		return &googleUserInfo{ID: "g-1", Email: "g@example.com", Name: "G"}, nil
	}

	resp, err := svc.GoogleCallback(context.Background(), "code", LoginContext{UserAgent: "ua", IP: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	s := e.sessionByRefresh(t, resp.Tokens.RefreshToken)
	if s.LoginMethod != session.MethodGoogle || s.IP != "10.0.0.1" {
		t.Fatalf("session: %+v", s)
	}
	if !e.securedOK(t, resp.Tokens.AccessToken) {
		t.Fatal("access token refused")
	}
	var u user.User
	if err := e.db.Where("google_id = ?", "g-1").First(&u).Error; err != nil {
		t.Fatal(err)
	}
	if w := e.refresh(t, resp.Tokens.RefreshToken); w.Code != http.StatusOK {
		t.Fatalf("a google session must refresh like any other: %d", w.Code)
	}
}

// A database failure must not read to the client as being signed out.
func TestRefreshLookupFailureIsNotASignOut(t *testing.T) {
	e := newEnv(t)
	tokens := e.login(t, e.addUser(t, entities.RoleUser))
	if err := e.db.Migrator().DropTable(&session.Session{}); err != nil {
		t.Fatal(err)
	}
	_, err := NewService(e.deps).RefreshTokens(context.Background(), tokens.RefreshToken, LoginContext{})
	apiErr, ok := err.(*apierr.APIError)
	if !ok || apiErr.Status != http.StatusInternalServerError {
		t.Fatalf("err = %v", err)
	}
}
