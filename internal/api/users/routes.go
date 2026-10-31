package users

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RegisterRoutes wires account management onto the admin group. The capability, not
// admin.users:update, is the gate: being able to edit a user must not imply being able to
// promote one.
func RegisterRoutes(admin *gin.RouterGroup, db *gorm.DB, recorder *auditlog.Recorder) {
	h := NewHandler(NewService(db, recorder))
	admin.PATCH("/users/:uuid/role", middleware.RequireCapability(authz.CapUsersRoleUpdate), h.ChangeRole)
}
