package example

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/note"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RegisterRoutes wires Note CRUD onto the secured (authenticated) group.
// This serves as a template — copy, rename, adapt for new features.
func RegisterRoutes(secured *gin.RouterGroup, db *gorm.DB) {
	noteRepo := repo.NewGormRepo[note.Note](db)
	h := NewHandler(noteRepo)

	notes := secured.Group("/notes")
	{
		notes.GET("", middleware.RequirePermission(authz.ResNote, authz.ActionRead), h.List)
		notes.POST("", middleware.RequirePermission(authz.ResNote, authz.ActionCreate), h.Create)
		notes.GET("/:uuid", middleware.RequirePermission(authz.ResNote, authz.ActionRead), h.Get)
		notes.PUT("/:uuid", middleware.RequirePermission(authz.ResNote, authz.ActionUpdate), h.Update)
		notes.DELETE("/:uuid", middleware.RequirePermission(authz.ResNote, authz.ActionDelete), h.Delete)
	}
}
