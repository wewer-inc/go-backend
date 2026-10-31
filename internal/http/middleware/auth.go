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

		if !sessionAlive(c, sessionRepo, claims, u.ID) {
			return false
		}

		c.Set(ctxActorUserID, u.ID)
		c.Set(ctxActorUserUUID, u.UUID.String())
		c.Set(ctxActorPlatformRole, u.PlatformRole)
		c.Set(ctxActorClaims, claims)
		// The role comes from the row just loaded, not the token, so a demotion takes
		// effect on the next request rather than when the token expires.
		c.Set(ctxActorSubject, authz.Subject{UserID: u.ID, Role: u.PlatformRole})

		return true
	}
}

// sessionAlive checks the token's session against the database, which is what makes
// revocation take effect on the next request rather than when the token expires. A token
// with no session cannot be revoked, so it is refused. A failed read is a 503, not a 401:
// an outage must not read to the client as being signed out.
func sessionAlive(c *gin.Context, sessionRepo repo.Repo[session.Session], claims *auth.Claims, userID uint) bool {
	sid, err := uuid.Parse(claims.SID)
	if err != nil {
		unauthorized(c, "invalid or expired token")
		return false
	}
	sess, err := sessionRepo.GetOne(c.Request.Context(), store.QueryOpts{Filters: map[string]any{"uuid": sid}})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		unauthorized(c, "session revoked")
		return false
	}
	if err != nil {
		_ = c.Error(err)
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, apicommon.Response[any]{Error: "auth_unavailable", Message: "session store unavailable"})
		return false
	}
	if sess.UserID != userID || sess.RevokedAt != nil || time.Now().After(sess.AbsoluteExpiry) {
		unauthorized(c, "session revoked")
		return false
	}
	return true
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
