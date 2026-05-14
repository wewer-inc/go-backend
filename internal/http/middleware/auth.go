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
)

const (
	ctxActorUserID       = "actor_user_id"
	ctxActorUserUUID     = "actor_user_uuid"
	ctxActorPlatformRole = "actor_platform_role"
)

// UserAuth validates JWT and loads the user into context.
func UserAuth(
	verifier auth.Verifier,
	userRepo repo.Repo[user.User],
) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, apicommon.Response[any]{Error: "unauthorized"})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			c.JSON(http.StatusUnauthorized, apicommon.Response[any]{Error: "unauthorized"})
			c.Abort()
			return
		}

		sub, err := verifier.Verify(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, apicommon.Response[any]{Error: "invalid or expired token"})
			c.Abort()
			return
		}

		userUUID, err := uuid.Parse(sub)
		if err != nil {
			c.JSON(http.StatusUnauthorized, apicommon.Response[any]{Error: "invalid token subject"})
			c.Abort()
			return
		}

		u, err := userRepo.GetByUUID(c.Request.Context(), userUUID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, apicommon.Response[any]{Error: "user not found"})
			c.Abort()
			return
		}

		c.Set(ctxActorUserID, u.ID)
		c.Set(ctxActorUserUUID, u.UUID.String())
		c.Set(ctxActorPlatformRole, u.PlatformRole)

		c.Next()
	}
}

// AdminAuth wraps UserAuth and additionally enforces admin role.
func AdminAuth(
	verifier auth.Verifier,
	userRepo repo.Repo[user.User],
) gin.HandlerFunc {
	userAuth := UserAuth(verifier, userRepo)

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
