package auth

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

// Deps is what the auth module needs.
type Deps struct {
	Cfg    config.Config
	DB     *gorm.DB
	Issuer platformauth.Issuer
	Redis  *goredis.Client // optional
	Audit  *auditlog.Recorder
	Log    zerolog.Logger
	// AuthLimit, if non-nil, is the strict rate limit on the public endpoints.
	AuthLimit gin.HandlerFunc
}

// RegisterRoutes wires auth endpoints.
//   - v1 is the unprotected /v1 group (login/register/refresh need no JWT).
//   - secured is the authenticated group (UserAuth applied).
func RegisterRoutes(v1, secured *gin.RouterGroup, d Deps) {
	svc := NewService(d)
	h := NewHandler(svc, d.Cfg.Env == "prod")

	pub := v1.Group("/auth")
	if d.AuthLimit != nil {
		pub.Use(d.AuthLimit)
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
		sec.GET("/sessions", h.ListSessions)
		sec.DELETE("/sessions", h.RevokeOtherSessions)
		sec.DELETE("/sessions/:sid", h.RevokeSession)
	}
}
