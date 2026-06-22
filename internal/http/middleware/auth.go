package middleware

import (
	"net/http"
	"strings"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
)

const (
	ctxActorUserID       = "actor_user_id"
	ctxActorUserUUID     = "actor_user_uuid"
	ctxActorPlatformRole = "actor_platform_role"
	ctxActorClaims       = "actor_claims"
)

// UserAuth validates a JWT access token and loads the user into context.
// redis may be nil (revocation checks are then skipped).
func UserAuth(
	verifier auth.Verifier,
	userRepo repo.Repo[user.User],
	redis *goredis.Client,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			unauthorized(c, "unauthorized")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			unauthorized(c, "unauthorized")
			return
		}

		claims, err := verifier.Verify(parts[1])
		if err != nil {
			unauthorized(c, "invalid or expired token")
			return
		}

		// Reject refresh tokens (or anything not minted as an access token)
		// presented as a bearer credential.
		if claims.TokenUse != auth.UseAccess {
			unauthorized(c, "invalid or expired token")
			return
		}

		// Revocation check: a logged-out access token is denylisted by jti.
		if redis != nil && claims.JTI != "" {
			if n, err := redis.Exists(c.Request.Context(), auth.DenylistKey(claims.JTI)).Result(); err == nil && n > 0 {
				unauthorized(c, "token revoked")
				return
			}
		}

		userUUID, err := uuid.Parse(claims.Subject)
		if err != nil {
			unauthorized(c, "invalid token subject")
			return
		}

		u, err := userRepo.GetByUUID(c.Request.Context(), userUUID)
		if err != nil {
			unauthorized(c, "user not found")
			return
		}

		c.Set(ctxActorUserID, u.ID)
		c.Set(ctxActorUserUUID, u.UUID.String())
		c.Set(ctxActorPlatformRole, u.PlatformRole)
		c.Set(ctxActorClaims, claims)

		c.Next()
	}
}

// AdminAuth wraps UserAuth and additionally enforces admin role.
func AdminAuth(
	verifier auth.Verifier,
	userRepo repo.Repo[user.User],
	redis *goredis.Client,
) gin.HandlerFunc {
	userAuth := UserAuth(verifier, userRepo, redis)

	return func(c *gin.Context) {
		userAuth(c)
		if c.IsAborted() {
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
