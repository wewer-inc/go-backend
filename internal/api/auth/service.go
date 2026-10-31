package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/passwordhistory"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/passwordreset"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/email"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

// codeRefreshRetry tells a client to try again with its latest token: another refresh
// rotated first and nothing is wrong with the session. The status is 409 since many
// clients read any 401 from the refresh endpoint as a sign-out.
const codeRefreshRetry = "refresh_retry"

// maxUserAgentLen bounds what is stored from a header the client fully controls.
const maxUserAgentLen = 512

// LoginContext is the client behind a request, stored on its session.
type LoginContext struct {
	UserAgent string
	IP        string
}

// Service handles authentication business logic.
type Service struct {
	db          *gorm.DB
	userRepo    repo.Repo[user.User]
	sessionRepo repo.Repo[session.Session]
	issuer      platformauth.Issuer
	redis       *goredis.Client
	audit       *auditlog.Recorder
	googleOAuth *oauth2.Config
	// fetchGoogleUser is a field because the userinfo URL is Google's, not configurable.
	fetchGoogleUser func(ctx context.Context, client *http.Client) (*googleUserInfo, error)
	log             zerolog.Logger

	resetRepo   repo.Repo[passwordreset.Token]
	historyRepo repo.Repo[passwordhistory.Entry]
	lockout     *lockout
	mailer      email.Mailer
	jobs        JobQueue

	refreshTTL  time.Duration
	absoluteTTL time.Duration
	raceWindow  time.Duration

	resetTTL      time.Duration
	resetCooldown time.Duration
	resetURL      string
	historyCount  int
}

// NewService builds the service. d.Redis may be nil: sessions live in Postgres, and
// Redis only adds the access-token denylist.
func NewService(d Deps) *Service {
	var googleOAuth *oauth2.Config
	if d.Cfg.Google.ClientID != "" {
		googleOAuth = &oauth2.Config{
			ClientID:     d.Cfg.Google.ClientID,
			ClientSecret: d.Cfg.Google.ClientSecret,
			RedirectURL:  d.Cfg.Google.RedirectURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     google.Endpoint,
		}
	}

	return &Service{
		db:              d.DB,
		userRepo:        repo.NewGormRepo[user.User](d.DB),
		sessionRepo:     repo.NewGormRepo[session.Session](d.DB),
		issuer:          d.Issuer,
		redis:           d.Redis,
		audit:           d.Audit,
		googleOAuth:     googleOAuth,
		fetchGoogleUser: fetchGoogleUserInfo,
		log:             d.Log,
		resetRepo:       repo.NewGormRepo[passwordreset.Token](d.DB),
		historyRepo:     repo.NewGormRepo[passwordhistory.Entry](d.DB),
		lockout: &lockout{
			db:        d.DB,
			threshold: d.Cfg.AuthSecurity.LockoutThreshold,
			window:    d.Cfg.AuthSecurity.LockoutWindow,
		},
		mailer:        d.Mailer,
		jobs:          d.Jobs,
		refreshTTL:    d.Cfg.JWT.RefreshTokenExpiry,
		absoluteTTL:   d.Cfg.AuthSecurity.SessionAbsoluteTTL,
		raceWindow:    d.Cfg.AuthSecurity.RefreshRaceWindow,
		resetTTL:      d.Cfg.AuthSecurity.PasswordResetTTL,
		resetCooldown: d.Cfg.AuthSecurity.PasswordResetCooldown,
		resetURL:      d.Cfg.AuthSecurity.PasswordResetURL,
		historyCount:  d.Cfg.AuthSecurity.PasswordHistoryCount,
	}
}

// Register creates a new user with email/password credentials.
func (s *Service) Register(ctx context.Context, req RegisterRequest, lc LoginContext) (*AuthResponse, error) {
	if platformauth.ValidatePassword(req.Password) != nil {
		return nil, weakPasswordError(req.Password)
	}

	exists, err := s.userRepo.Exists(ctx, store.QueryOpts{
		Filters: map[string]any{"email": req.Email},
	})
	if err != nil {
		return nil, apierr.Internal("failed to check existing user")
	}
	if exists {
		return nil, apierr.Conflict("email_taken", "email is already registered")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, apierr.Internal("failed to hash password")
	}

	u := &user.User{
		UUID:         uuid.New(),
		Email:        req.Email,
		Name:         req.Name,
		PasswordHash: string(hash),
		PlatformRole: entities.RoleUser,
	}

	if err := s.userRepo.Create(ctx, u); err != nil {
		return nil, apierr.Internal("failed to create user")
	}

	return s.issueSession(ctx, u, session.MethodPassword, lc)
}

// Login authenticates via email/password and starts a session.
func (s *Service) Login(ctx context.Context, req LoginRequest, lc LoginContext) (*AuthResponse, error) {
	remaining, err := s.lockout.retryAfter(ctx, req.Email)
	if err != nil {
		return nil, apierr.InternalErr(err, "lockout check failed")
	}
	if remaining > 0 {
		s.record(ctx, audit.EventLoginLocked, nil, lc.IP, nil)
		return nil, lockedError(remaining)
	}

	u, err := s.userRepo.GetOne(ctx, store.QueryOpts{
		Filters: map[string]any{"email": req.Email},
	})
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apierr.InternalErr(err, "login lookup failed")
		}
		s.countFailure(ctx, req.Email)
		// The address stays out of the row: people type passwords into the wrong field.
		s.record(ctx, audit.EventLoginFailure, nil, lc.IP, nil)
		return nil, apierr.Unauthorized("invalid credentials")
	}

	if u.PasswordHash == "" {
		return nil, apierr.BadRequest("oauth_only", "this account uses Google sign-in")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		s.countFailure(ctx, req.Email)
		s.record(ctx, audit.EventLoginFailure, &u.ID, lc.IP, nil)
		return nil, apierr.Unauthorized("invalid credentials")
	}

	if err := s.lockout.clear(ctx, req.Email); err != nil {
		s.log.Error().Err(err).Msg("auth: failed to clear the login failure count")
	}
	return s.issueSession(ctx, u, session.MethodPassword, lc)
}

// issueSession creates a session and the token pair for it.
func (s *Service) issueSession(ctx context.Context, u *user.User, method session.LoginMethod, lc LoginContext) (*AuthResponse, error) {
	refresh, err := platformauth.GenerateOpaqueToken()
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to generate refresh token")
	}

	now := time.Now().UTC()
	absolute := now.Add(s.absoluteTTL)
	sess := &session.Session{
		UUID:             uuid.New(),
		UserID:           u.ID,
		RefreshTokenHash: platformauth.HashToken(refresh),
		LoginMethod:      method,
		UserAgent:        lc.UserAgent,
		IP:               lc.IP,
		LastUsedAt:       now,
		ExpiresAt:        earliest(now.Add(s.refreshTTL), absolute),
		AbsoluteExpiry:   absolute,
	}
	if err := s.sessionRepo.Create(ctx, sess); err != nil {
		return nil, apierr.InternalErr(err, "failed to create session")
	}

	access, err := s.issuer.IssueAccessToken(platformauth.AccessParams{Subject: u.UUID.String(), SID: sess.UUID.String()})
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to issue access token")
	}

	s.record(ctx, audit.EventLoginSuccess, &u.ID, lc.IP, map[string]any{"method": string(method), "session": sess.UUID.String()})
	return authResponse(u, access.Token, refresh), nil
}

// RefreshTokens rotates the session a refresh token belongs to and returns new tokens.
//
// Expect concurrent calls as a matter of routine. A page loading several resources just
// after its access token lapses fires several refreshes carrying one token. Only one of
// them rotates; the rest get a refusal they can retry, and the session stays valid.
func (s *Service) RefreshTokens(ctx context.Context, refreshToken string, lc LoginContext) (*AuthResponse, error) {
	hash := platformauth.HashToken(refreshToken)
	now := time.Now().UTC()

	sess, err := s.sessionRepo.GetOne(ctx, store.QueryOpts{Filters: map[string]any{"refresh_token_hash": hash}})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, s.judgeRetiredToken(ctx, hash, lc)
	}
	if err != nil {
		return nil, apierr.InternalErr(err, "refresh lookup failed")
	}

	if err := s.checkRefreshable(ctx, sess, now); err != nil {
		return nil, err
	}
	u, err := s.userRepo.GetByID(ctx, sess.UserID)
	if err != nil {
		return nil, apierr.UnauthorizedCode("session_expired", "user not found")
	}

	newRefresh, err := platformauth.GenerateOpaqueToken()
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to generate refresh token")
	}
	// Minted before the rotation, so a failure here leaves the client's token valid.
	access, err := s.issuer.IssueAccessToken(platformauth.AccessParams{Subject: u.UUID.String(), SID: sess.UUID.String()})
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to issue access token")
	}

	// A compare-and-set on the hash we read: of two requests holding the same token only
	// one writes, so nobody walks away with a token that matches no row. The revoked_at
	// guard stops a rotation from answering after a concurrent sign-out.
	rotated, err := s.sessionRepo.UpdateColumnsGuarded(ctx, sess.ID,
		map[string]any{"refresh_token_hash": hash, "revoked_at": nil},
		nil,
		map[string]any{
			"refresh_token_hash":      platformauth.HashToken(newRefresh),
			"prev_refresh_token_hash": hash,
			"rotated_at":              now,
			"last_used_at":            now,
			"expires_at":              earliest(now.Add(s.refreshTTL), sess.AbsoluteExpiry),
		})
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to rotate session")
	}
	if !rotated {
		return nil, s.raceRefusal(ctx, sess, lc)
	}

	s.record(ctx, audit.EventTokenRefresh, &u.ID, lc.IP, map[string]any{"session": sess.UUID.String()})
	return authResponse(u, access.Token, newRefresh), nil
}

// judgeRetiredToken handles a hash that matches no session's current token, and every
// path through it ends in an error.
//
// Matching the previous hash says the token was this session's one generation ago. If the
// rotation is younger than the race window, this is a concurrent caller that lost, and the
// session is left alone. Older than that, every legitimate holder has long had the
// replacement, so this is the replay the control exists for and the session is revoked.
func (s *Service) judgeRetiredToken(ctx context.Context, hash string, lc LoginContext) error {
	reused, err := s.sessionRepo.GetOne(ctx, store.QueryOpts{Filters: map[string]any{"prev_refresh_token_hash": hash}})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return apierr.UnauthorizedCode("session_expired", "invalid refresh token")
	}
	if err != nil {
		return apierr.InternalErr(err, "refresh lookup failed")
	}
	if reused.RevokedAt != nil {
		return apierr.UnauthorizedCode("session_expired", "session revoked")
	}
	if reused.RotatedAt != nil && time.Since(*reused.RotatedAt) <= s.raceWindow {
		return s.raceRefusal(ctx, reused, lc)
	}

	if err := s.revokeSession(ctx, reused); err != nil {
		return err
	}
	s.record(ctx, audit.EventRefreshReuse, &reused.UserID, lc.IP, map[string]any{"session": reused.UUID.String()})
	return apierr.UnauthorizedCode("session_expired", "refresh token reuse detected")
}

func (s *Service) raceRefusal(ctx context.Context, sess *session.Session, lc LoginContext) error {
	s.record(ctx, audit.EventRefreshRace, &sess.UserID, lc.IP, map[string]any{"session": sess.UUID.String()})
	return apierr.Conflict(codeRefreshRetry, "refresh token already rotated; retry with the latest token")
}

// checkRefreshable refuses a session that is impersonated, revoked or past either expiry.
func (s *Service) checkRefreshable(ctx context.Context, sess *session.Session, now time.Time) error {
	// An impersonated session is created with a hash nobody can redeem, so getting this far
	// signals a fault. It is revoked and refused, which keeps the session's TTL final.
	if sess.ImpersonatorUserID != nil {
		if err := s.revokeSession(ctx, sess); err != nil {
			return err
		}
		return apierr.UnauthorizedCode("session_expired", "impersonation sessions cannot be refreshed")
	}
	if sess.RevokedAt != nil {
		return apierr.UnauthorizedCode("session_expired", "session revoked")
	}
	if now.After(sess.AbsoluteExpiry) || now.After(sess.ExpiresAt) {
		return apierr.UnauthorizedCode("session_expired", "session expired; please sign in again")
	}
	return nil
}

// Logout revokes the current session and denylists the presented access token. An
// optional refresh token must belong to the same user: nobody can sign out someone else.
func (s *Service) Logout(ctx context.Context, userID uint, claims *platformauth.Claims, refreshToken, ip string) error {
	if claims == nil {
		return apierr.Unauthorized("missing authentication")
	}

	var other *session.Session
	if refreshToken != "" {
		found, err := s.sessionRepo.GetOne(ctx, store.QueryOpts{
			Filters: map[string]any{"refresh_token_hash": platformauth.HashToken(refreshToken)},
		})
		switch {
		case err == nil:
			if found.UserID != userID {
				return apierr.Forbidden("refresh token does not belong to the authenticated user")
			}
			other = found
		case !errors.Is(err, gorm.ErrRecordNotFound):
			return apierr.InternalErr(err, "session lookup failed")
		}
	}

	current, err := s.sessionByUUID(ctx, claims.SID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return apierr.InternalErr(err, "session lookup failed")
	}
	if err == nil {
		if err := s.revokeSession(ctx, current); err != nil {
			return err
		}
	}
	if other != nil {
		if err := s.revokeSession(ctx, other); err != nil {
			return err
		}
	}

	// The session row is what makes the token dead, so a denylist failure is not a failed
	// logout. The denylist still spares a database read on the token's next use.
	if s.redis != nil && claims.JTI != "" {
		if ttl := time.Until(claims.ExpiresAt); ttl > 0 {
			if err := s.redis.Set(ctx, platformauth.DenylistKey(claims.JTI), "1", ttl).Err(); err != nil {
				s.log.Warn().Err(err).Msg("auth: failed to denylist access token after revoking its session")
			}
		}
	}

	s.record(ctx, audit.EventLogout, &userID, ip, map[string]any{"session": claims.SID})
	return nil
}

// GoogleAuthURL returns the OAuth2 redirect URL with the given state.
func (s *Service) GoogleAuthURL(state string) (string, error) {
	if s.googleOAuth == nil {
		return "", apierr.Internal("google oauth not configured")
	}
	return s.googleOAuth.AuthCodeURL(state, oauth2.AccessTypeOffline), nil
}

// GoogleCallback exchanges an auth code for user info and upserts the user.
func (s *Service) GoogleCallback(ctx context.Context, code string, lc LoginContext) (*AuthResponse, error) {
	if s.googleOAuth == nil {
		return nil, apierr.Internal("google oauth not configured")
	}

	token, err := s.googleOAuth.Exchange(ctx, code)
	if err != nil {
		return nil, apierr.BadRequest("google_exchange_failed", "could not exchange code")
	}

	info, err := s.fetchGoogleUser(ctx, s.googleOAuth.Client(ctx, token))
	if err != nil {
		return nil, apierr.Internal("could not fetch google user info")
	}

	u, err := s.upsertGoogleUser(ctx, info)
	if err != nil {
		return nil, err
	}
	return s.issueSession(ctx, u, session.MethodGoogle, lc)
}

func (s *Service) upsertGoogleUser(ctx context.Context, info *googleUserInfo) (*user.User, error) {
	u, err := s.userRepo.GetOne(ctx, store.QueryOpts{
		Filters: map[string]any{"google_id": info.ID},
	})
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, apierr.Internal("db lookup failed")
	}

	u, err = s.userRepo.GetOne(ctx, store.QueryOpts{
		Filters: map[string]any{"email": info.Email},
	})
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, apierr.Internal("db lookup failed")
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		u = &user.User{
			UUID:         uuid.New(),
			Email:        info.Email,
			Name:         info.Name,
			GoogleID:     info.ID,
			AvatarURL:    info.Picture,
			PlatformRole: entities.RoleUser,
		}
		if err := s.userRepo.Create(ctx, u); err != nil {
			return nil, apierr.Internal("failed to create user")
		}
		return u, nil
	}

	if err := s.userRepo.UpdateColumnsByID(ctx, u.ID, map[string]any{
		"google_id":  info.ID,
		"avatar_url": info.Picture,
	}); err != nil {
		return nil, apierr.Internal("failed to link google account")
	}
	u.GoogleID = info.ID
	u.AvatarURL = info.Picture
	return u, nil
}

func authResponse(u *user.User, access, refresh string) *AuthResponse {
	return &AuthResponse{
		User: UserResponse{
			UUID:         u.UUID.String(),
			Name:         u.Name,
			Email:        u.Email,
			AvatarURL:    u.AvatarURL,
			PlatformRole: string(u.PlatformRole),
		},
		Tokens: TokenPairResponse{AccessToken: access, RefreshToken: refresh},
	}
}

func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// record writes an audit row where losing it must not fail the caller, such as a login.
// The recorder has already logged the failure.
func (s *Service) record(ctx context.Context, event string, actor *uint, ip string, detail map[string]any) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, auditlog.Entry{Event: event, ActorUserID: actor, IP: ip, Detail: detail})
}

// recordRequired writes an audit row inside a transaction, where its failure must undo
// the change: a privileged action with no record is worse than one that did not happen.
func (s *Service) recordRequired(ctx context.Context, e auditlog.Entry) error {
	if s.audit == nil {
		return nil
	}
	if err := s.audit.Record(ctx, e); err != nil {
		return apierr.InternalErr(err, "failed to record audit event")
	}
	return nil
}

type googleUserInfo struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

func fetchGoogleUserInfo(ctx context.Context, client *http.Client) (*googleUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google userinfo status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var info googleUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	return &info, nil
}
