package auth

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/email"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/worker"
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
	Mailer email.Mailer
	Jobs   JobQueue
	// AuthLimit, if non-nil, is the strict rate limit on the public endpoints.
	AuthLimit gin.HandlerFunc
}

// JobQueue is the part of worker.Worker this module uses.
type JobQueue interface {
	Enqueue(job worker.Job) error
}

// RegisterRoutes wires auth endpoints.
//   - v1 is the unprotected /v1 group (login/register/refresh need no JWT).
//   - secured is the authenticated group (UserAuth applied).
//   - admin is the /v1/admin group.
func RegisterRoutes(v1, secured, admin *gin.RouterGroup, d Deps) {
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
		pub.POST("/forgot-password", h.ForgotPassword)
		pub.POST("/reset-password", h.ResetPassword)
		pub.POST("/mfa/verify", h.MFAVerify)
		pub.GET("/google", h.GoogleRedirect)
		pub.GET("/google/callback", h.GoogleCallback)
	}

	// Authenticated auth endpoints.
	sec := secured.Group("/auth")
	{
		sec.POST("/logout", h.Logout)
		sec.GET("/permissions", h.Permissions)
		sec.GET("/sessions", h.ListSessions)
		sec.GET("/mfa/status", h.MFAStatus)
		sec.POST("/impersonate/end", h.EndImpersonation)
	}

	// The account's own credentials and sessions, which a login-as session must not touch.
	own := sec.Group("")
	own.Use(middleware.RefuseImpersonated())
	{
		own.POST("/change-password", h.ChangePassword)
		own.DELETE("/sessions", h.RevokeOtherSessions)
		own.DELETE("/sessions/:sid", h.RevokeSession)
		own.POST("/mfa/enroll/start", h.MFAEnrollStart)
		own.POST("/mfa/enroll/confirm", h.MFAEnrollConfirm)
		own.POST("/mfa/backup-codes/regenerate", h.MFARegenerateBackupCodes)
	}

	admin.POST("/users/:uuid/mfa/reset", middleware.RequireCapability(authz.CapUsersMFAReset), h.AdminResetMFA)
	admin.POST("/users/:uuid/impersonate", middleware.RequireCapability(authz.CapUsersImpersonate), h.StartImpersonation)
}
