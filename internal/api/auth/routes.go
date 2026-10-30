package auth

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
)

// RegisterRoutes wires auth endpoints.
//   - v1 is the unprotected /v1 group (login/register/refresh need no JWT).
//   - secured is the authenticated group (UserAuth applied) used for logout.
//   - authLimit, if non-nil, is a stricter rate-limit middleware applied only to
//     the brute-force-sensitive public auth endpoints.
func RegisterRoutes(
	v1 *gin.RouterGroup,
	secured *gin.RouterGroup,
	cfg config.Config,
	userRepo repo.Repo[user.User],
	issuer platformauth.Issuer,
	verifier platformauth.Verifier,
	redis *goredis.Client,
	authLimit gin.HandlerFunc,
) {
	svc := NewService(userRepo, issuer, verifier, redis, cfg)
	h := NewHandler(svc, cfg.Env == "prod")

	pub := v1.Group("/auth")
	if authLimit != nil {
		pub.Use(authLimit)
	}
	{
		pub.POST("/register", h.Register)
		pub.POST("/login", h.Login)
		pub.POST("/refresh", h.Refresh)
		pub.GET("/google", h.GoogleRedirect)
		pub.GET("/google/callback", h.GoogleCallback)
	}

	// Authenticated auth endpoints.
	sec := secured.Group("/auth")
	{
		sec.POST("/logout", h.Logout)
		sec.GET("/permissions", h.Permissions)
	}
}
