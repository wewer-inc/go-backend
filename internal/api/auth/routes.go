package auth

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
)

// RegisterRoutes wires auth endpoints onto the provided router group.
// v1 is the unprotected /v1 group (no JWT required for login/register).
func RegisterRoutes(
	v1 *gin.RouterGroup,
	cfg config.Config,
	userRepo repo.Repo[user.User],
	issuer platformauth.Issuer,
	verifier platformauth.Verifier,
	redis *goredis.Client,
) {
	svc := NewService(userRepo, issuer, verifier, redis, cfg)
	h := NewHandler(svc)

	auth := v1.Group("/auth")
	{
		auth.POST("/register", h.Register)
		auth.POST("/login", h.Login)
		auth.POST("/refresh", h.Refresh)
		auth.GET("/google", h.GoogleRedirect)
		auth.GET("/google/callback", h.GoogleCallback)
	}
}
