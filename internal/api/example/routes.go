package example

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/note"
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
		notes.GET("", h.List)
		notes.POST("", h.Create)
		notes.GET("/:uuid", h.Get)
		notes.PUT("/:uuid", h.Update)
		notes.DELETE("/:uuid", h.Delete)
	}
}
