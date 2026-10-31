package adminaudit

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RegisterRoutes mounts audit listing and chain verification, both GETs, under admin.
func RegisterRoutes(admin *gin.RouterGroup, db *gorm.DB) {
	h := NewHandler(repo.NewGormRepo[audit.Log](db), db)
	read := middleware.RequirePermission(authz.ResAdminAudit, authz.ActionRead)
	admin.GET("/audit", read, h.List)
	admin.GET("/audit/verify", read, h.Verify)
}
