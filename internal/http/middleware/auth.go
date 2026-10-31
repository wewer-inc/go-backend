package middleware

import (
	"errors"
	"net/http"
	"strings"
	"time"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

const (
	ctxActorUserID       = "actor_user_id"
	ctxActorUserUUID     = "actor_user_uuid"
	ctxActorPlatformRole = "actor_platform_role"
	ctxActorClaims       = "actor_claims"
)

// UserAuth validates a JWT access token, checks its session is still live, and loads the
// user into context. redis may be nil, which skips only the jti denylist: the session
// check does not need it. revocationFailOpen decides behaviour when the denylist cannot
// be queried: true accepts the token, false rejects with 503.
func UserAuth(
	verifier auth.Verifier,
	userRepo repo.Repo[user.User],
	sessionRepo repo.Repo[session.Session],
	redis *goredis.Client,
	revocationFailOpen bool,
) gin.HandlerFunc {
	authenticate := authenticator(verifier, userRepo, sessionRepo, redis, revocationFailOpen)
	return func(c *gin.Context) {
		if authenticate(c) {
			c.Next()
		}
	}
}

// authenticator verifies the request and sets the actor on the context. It reports
// whether the request may proceed, having already answered when it may not. It never
// calls c.Next, so a caller can add its own check before the rest of the chain runs.
func authenticator(
	verifier auth.Verifier,
	userRepo repo.Repo[user.User],
	sessionRepo repo.Repo[session.Session],
	redis *goredis.Client,
	revocationFailOpen bool,
) func(c *gin.Context) bool {
	return func(c *gin.Context) bool {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			unauthorized(c, "unauthorized")
			return false
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			unauthorized(c, "unauthorized")
			return false
		}

		claims, err := verifier.Verify(parts[1])
		if err != nil {
			unauthorized(c, "invalid or expired token")
			return false
		}

		// Reject refresh tokens (or anything not minted as an access token)
		// presented as a bearer credential.
		if claims.TokenUse != auth.UseAccess {
			unauthorized(c, "invalid or expired token")
			return false
		}

		// Revocation check: a logged-out access token is denylisted by jti.
		if redis != nil && claims.JTI != "" {
			n, err := redis.Exists(c.Request.Context(), auth.DenylistKey(claims.JTI)).Result()
			switch {
			case err != nil && !revocationFailOpen:
				// Fail closed: cannot prove the token is still valid.
				c.JSON(http.StatusServiceUnavailable, apicommon.Response[any]{Error: "auth_unavailable", Message: "revocation store unavailable"})
				c.Abort()
				return false
			case err == nil && n > 0:
				unauthorized(c, "token revoked")
				return false
			}
		}

		userUUID, err := uuid.Parse(claims.Subject)
		if err != nil {
			unauthorized(c, "invalid token subject")
			return false
		}

		u, err := userRepo.GetByUUID(c.Request.Context(), userUUID)
		if err != nil {
			unauthorized(c, "user not found")
			return false
		}

		sess, ok := liveSession(c, sessionRepo, claims, u.ID)
		if !ok {
			return false
		}
		// The token and the row must agree on who is behind the session. A token claiming an
		// actor its session does not name, or hiding one it does, is refused.
		if !sameImpersonator(claims.Impersonator, sess.ImpersonatorUserID) {
			unauthorized(c, "invalid or expired token")
			return false
		}

		// The role is read from the user row loaded above and ignored in the token, so a
		// demotion applies from the very next request.
		subject := authz.Subject{UserID: u.ID, Role: u.PlatformRole}
		if claims.Impersonator != 0 {
			impersonator := claims.Impersonator
			subject.Impersonator = &impersonator
			// Carrying the id on the context means audit rows written later in this
			// request name the impersonator without each handler passing it along.
			c.Request = c.Request.WithContext(auditlog.ContextWithImpersonator(c.Request.Context(), impersonator))
		}

		c.Set(ctxActorUserID, u.ID)
		c.Set(ctxActorUserUUID, u.UUID.String())
		c.Set(ctxActorPlatformRole, u.PlatformRole)
		c.Set(ctxActorClaims, claims)
		c.Set(ctxActorSubject, subject)

		return true
	}
}

// liveSession loads the token's session and rejects it if it is gone, revoked, expired or
// someone else's. Doing this on every request is how a revocation can apply at once, and
// a token with no session is rejected because it could never be revoked. A failed read
// answers 503 so that a database outage does not look like a sign-out to the client.
func liveSession(c *gin.Context, sessionRepo repo.Repo[session.Session], claims *auth.Claims, userID uint) (*session.Session, bool) {
	sid, err := uuid.Parse(claims.SID)
	if err != nil {
		unauthorized(c, "invalid or expired token")
		return nil, false
	}
	sess, err := sessionRepo.GetOne(c.Request.Context(), store.QueryOpts{Filters: map[string]any{"uuid": sid}})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		unauthorized(c, "session revoked")
		return nil, false
	}
	if err != nil {
		_ = c.Error(err)
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, apicommon.Response[any]{Error: "auth_unavailable", Message: "session store unavailable"})
		return nil, false
	}
	if sess.UserID != userID || sess.RevokedAt != nil || time.Now().After(sess.AbsoluteExpiry) {
		unauthorized(c, "session revoked")
		return nil, false
	}
	return sess, true
}

func sameImpersonator(claim uint, row *uint) bool {
	if row == nil {
		return claim == 0
	}
	return claim == *row
}

// AdminAuth authenticates like UserAuth and additionally enforces admin role, before
// anything downstream runs.
func AdminAuth(
	verifier auth.Verifier,
	userRepo repo.Repo[user.User],
	sessionRepo repo.Repo[session.Session],
	redis *goredis.Client,
	revocationFailOpen bool,
) gin.HandlerFunc {
	authenticate := authenticator(verifier, userRepo, sessionRepo, redis, revocationFailOpen)

	return func(c *gin.Context) {
		if !authenticate(c) {
			return
		}

		role, _ := GetActorPlatformRole(c)
		if role != entities.RoleAdmin {
			c.JSON(http.StatusForbidden, apicommon.Response[any]{Error: "forbidden: admin access required"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func unauthorized(c *gin.Context, msg string) {
	c.JSON(http.StatusUnauthorized, apicommon.Response[any]{Error: msg})
	c.Abort()
}

func GetActorUserID(c *gin.Context) (uint, bool) {
	v, ok := c.Get(ctxActorUserID)
	id, ok2 := v.(uint)
	return id, ok && ok2
}

func GetActorUserUUID(c *gin.Context) (string, bool) {
	v, ok := c.Get(ctxActorUserUUID)
	s, ok2 := v.(string)
	return s, ok && ok2
}

func GetActorPlatformRole(c *gin.Context) (entities.Role, bool) {
	v, ok := c.Get(ctxActorPlatformRole)
	role, ok2 := v.(entities.Role)
	return role, ok && ok2
}

// GetActorClaims returns the verified access-token claims for the request.
func GetActorClaims(c *gin.Context) (*auth.Claims, bool) {
	v, ok := c.Get(ctxActorClaims)
	claims, ok2 := v.(*auth.Claims)
	return claims, ok && ok2
}
