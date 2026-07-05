package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

const refreshTokenPrefix = "refresh_token:"

// refreshKey scopes a refresh token to a single session (sub + jti) so that
// logging in on a second device does not invalidate the first, and a single
// session can be revoked independently of the rest.
func refreshKey(sub, jti string) string {
	return refreshTokenPrefix + sub + ":" + jti
}

// hashRefreshToken returns a hex SHA-256 of the refresh token. Only the hash is
// stored server-side, so a Redis snapshot/dump never exposes usable bearer
// tokens.
func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Service handles authentication business logic.
type Service struct {
	userRepo    repo.Repo[user.User]
	issuer      platformauth.Issuer
	verifier    platformauth.Verifier
	redis       *goredis.Client
	googleOAuth *oauth2.Config
	jwtCfg      config.JWTConfig
}

func NewService(
	userRepo repo.Repo[user.User],
	issuer platformauth.Issuer,
	verifier platformauth.Verifier,
	redis *goredis.Client,
	cfg config.Config,
) *Service {
	var googleOAuth *oauth2.Config
	if cfg.Google.ClientID != "" {
		googleOAuth = &oauth2.Config{
			ClientID:     cfg.Google.ClientID,
			ClientSecret: cfg.Google.ClientSecret,
			RedirectURL:  cfg.Google.RedirectURL,
			Scopes:       []string{"openid", "profile", "email"},
			Endpoint:     google.Endpoint,
		}
	}

	return &Service{
		userRepo:    userRepo,
		issuer:      issuer,
		verifier:    verifier,
		redis:       redis,
		googleOAuth: googleOAuth,
		jwtCfg:      cfg.JWT,
	}
}

// Register creates a new user with email/password credentials.
func (s *Service) Register(ctx context.Context, req RegisterRequest) (*AuthResponse, error) {
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

	return s.issueTokenPair(ctx, u)
}

// Login authenticates via email/password and returns a token pair.
func (s *Service) Login(ctx context.Context, req LoginRequest) (*AuthResponse, error) {
	u, err := s.userRepo.GetOne(ctx, store.QueryOpts{
		Filters: map[string]any{"email": req.Email},
	})
	if err != nil {
		return nil, apierr.Unauthorized("invalid credentials")
	}

	if u.PasswordHash == "" {
		return nil, apierr.BadRequest("oauth_only", "this account uses Google sign-in")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		return nil, apierr.Unauthorized("invalid credentials")
	}

	return s.issueTokenPair(ctx, u)
}

// RefreshTokens exchanges a valid refresh token for a new token pair.
func (s *Service) RefreshTokens(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	claims, err := s.verifier.Verify(refreshToken)
	if err != nil {
		return nil, apierr.Unauthorized("invalid or expired refresh token")
	}

	// Reject access tokens (or anything that isn't a refresh token) presented here.
	if claims.TokenUse != platformauth.UseRefresh {
		return nil, apierr.Unauthorized("invalid or expired refresh token")
	}

	key := refreshKey(claims.Subject, claims.JTI)

	// Atomically fetch-and-delete the stored hash. GETDEL makes rotation
	// race-free: of two concurrent refreshes for the same token, only one sees
	// the value — the other gets redis.Nil and is rejected, so a single refresh
	// token can never mint two live sessions.
	stored, err := s.redis.GetDel(ctx, key).Result()
	if err != nil {
		return nil, apierr.Unauthorized("refresh token not recognised")
	}
	// Constant-time compare against the presented token's hash.
	if subtle.ConstantTimeCompare([]byte(stored), []byte(hashRefreshToken(refreshToken))) != 1 {
		return nil, apierr.Unauthorized("refresh token not recognised")
	}

	userUUID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, apierr.Unauthorized("invalid token subject")
	}

	u, err := s.userRepo.GetByUUID(ctx, userUUID)
	if err != nil {
		return nil, apierr.Unauthorized("user not found")
	}

	return s.issueTokenPair(ctx, u)
}

// Logout revokes the current session: it denylists the presented access token
// (by jti, until it would have expired) and deletes the refresh session so it
// can no longer be exchanged. The optional refresh token must belong to the
// same subject as the access token — a user cannot revoke someone else's session.
func (s *Service) Logout(ctx context.Context, accessClaims *platformauth.Claims, refreshToken string) error {
	if accessClaims == nil {
		return apierr.Unauthorized("missing authentication")
	}

	// Revoke the access token. This is a guarantee, not best-effort: if the
	// denylist write fails, logout fails so the caller knows the token is still
	// live.
	if accessClaims.JTI != "" {
		ttl := time.Until(accessClaims.ExpiresAt)
		if ttl > 0 {
			if err := s.redis.Set(ctx, platformauth.DenylistKey(accessClaims.JTI), "1", ttl).Err(); err != nil {
				return apierr.Internal("failed to revoke access token")
			}
		}
	}

	if refreshToken != "" {
		rc, err := s.verifier.Verify(refreshToken)
		// Ignore a malformed/expired refresh token — access revocation already
		// happened. But a *valid* token for another subject is an attempt to
		// revoke a session that isn't the caller's: reject it.
		if err == nil && rc.TokenUse == platformauth.UseRefresh {
			if rc.Subject != accessClaims.Subject {
				return apierr.Forbidden("refresh token does not belong to the authenticated user")
			}
			if err := s.redis.Del(ctx, refreshKey(rc.Subject, rc.JTI)).Err(); err != nil {
				return apierr.Internal("failed to revoke refresh session")
			}
		}
	}

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
func (s *Service) GoogleCallback(ctx context.Context, code string) (*AuthResponse, error) {
	if s.googleOAuth == nil {
		return nil, apierr.Internal("google oauth not configured")
	}

	token, err := s.googleOAuth.Exchange(ctx, code)
	if err != nil {
		return nil, apierr.BadRequest("google_exchange_failed", "could not exchange code")
	}

	info, err := fetchGoogleUserInfo(ctx, s.googleOAuth.Client(ctx, token))
	if err != nil {
		return nil, apierr.Internal("could not fetch google user info")
	}

	u, err := s.userRepo.GetOne(ctx, store.QueryOpts{
		Filters: map[string]any{"google_id": info.ID},
	})

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, apierr.Internal("db lookup failed")
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
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
		} else {
			if err := s.userRepo.UpdateColumnsByID(ctx, u.ID, map[string]any{
				"google_id":  info.ID,
				"avatar_url": info.Picture,
			}); err != nil {
				return nil, apierr.Internal("failed to link google account")
			}
			u.GoogleID = info.ID
			u.AvatarURL = info.Picture
		}
	}

	return s.issueTokenPair(ctx, u)
}

func (s *Service) issueTokenPair(ctx context.Context, u *user.User) (*AuthResponse, error) {
	uuidStr := u.UUID.String()

	access, err := s.issuer.IssueAccessToken(uuidStr)
	if err != nil {
		return nil, apierr.Internal("failed to issue access token")
	}

	refresh, err := s.issuer.IssueRefreshToken(uuidStr)
	if err != nil {
		return nil, apierr.Internal("failed to issue refresh token")
	}

	// Store only the hash of the refresh token under a per-session key so
	// concurrent sessions (multiple devices) coexist and can be revoked
	// individually, and a Redis dump never leaks usable tokens.
	key := refreshKey(uuidStr, refresh.JTI)
	if err := s.redis.Set(ctx, key, hashRefreshToken(refresh.Token), s.jwtCfg.RefreshTokenExpiry).Err(); err != nil {
		return nil, apierr.Internal("failed to store refresh token")
	}

	return &AuthResponse{
		User: UserResponse{
			UUID:         uuidStr,
			Name:         u.Name,
			Email:        u.Email,
			AvatarURL:    u.AvatarURL,
			PlatformRole: string(u.PlatformRole),
		},
		Tokens: TokenPairResponse{
			AccessToken:  access.Token,
			RefreshToken: refresh.Token,
		},
	}, nil
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
