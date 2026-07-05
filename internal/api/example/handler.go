package example

import (
	"errors"
	"net/http"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/note"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Handler struct {
	repo repo.Repo[note.Note]
}

func NewHandler(r repo.Repo[note.Note]) *Handler {
	return &Handler{repo: r}
}

func (h *Handler) List(c *gin.Context) {
	userID, ok := middleware.GetActorUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, apicommon.Response[any]{Error: "unauthorized"})
		return
	}

	notes, page, err := h.repo.List(c.Request.Context(), store.QueryOpts{
		Filters:  map[string]any{"user_id": userID},
		Page:     1,
		PageSize: 20,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, apicommon.Response[any]{Error: "internal_error"})
		return
	}

	items := make([]NoteResponse, len(notes))
	for i := range notes {
		items[i] = toNoteResponse(&notes[i])
	}

	c.JSON(http.StatusOK, apicommon.PaginatedResponse[NoteResponse]{
		Data: items,
		Page: &apicommon.Pagination{
			Page:     page.Page,
			PageSize: page.PageSize,
			Total:    page.Total,
			HasNext:  page.HasNext,
		},
	})
}

func (h *Handler) Create(c *gin.Context) {
	userID, ok := middleware.GetActorUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, apicommon.Response[any]{Error: "unauthorized"})
		return
	}

	var req CreateNoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apicommon.Response[any]{Error: "validation_error", Message: "invalid request body"})
		return
	}

	n := &note.Note{
		UUID:   uuid.New(),
		UserID: userID,
		Title:  req.Title,
		Body:   req.Body,
	}

	if err := h.repo.Create(c.Request.Context(), n); err != nil {
		c.JSON(http.StatusInternalServerError, apicommon.Response[any]{Error: "internal_error"})
		return
	}

	resp := toNoteResponse(n)
	c.JSON(http.StatusCreated, apicommon.Response[NoteResponse]{Data: &resp})
}

func (h *Handler) Get(c *gin.Context) {
	n, ok := h.fetchOwnedNote(c)
	if !ok {
		return
	}
	resp := toNoteResponse(n)
	c.JSON(http.StatusOK, apicommon.Response[NoteResponse]{Data: &resp})
}

func (h *Handler) Update(c *gin.Context) {
	n, ok := h.fetchOwnedNote(c)
	if !ok {
		return
	}

	var req UpdateNoteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apicommon.Response[any]{Error: "validation_error", Message: "invalid request body"})
		return
	}

	if req.Title != "" {
		n.Title = req.Title
	}
	if req.Body != "" {
		n.Body = req.Body
	}

	if err := h.repo.Update(c.Request.Context(), n); err != nil {
		c.JSON(http.StatusInternalServerError, apicommon.Response[any]{Error: "internal_error"})
		return
	}

	resp := toNoteResponse(n)
	c.JSON(http.StatusOK, apicommon.Response[NoteResponse]{Data: &resp})
}

func (h *Handler) Delete(c *gin.Context) {
	n, ok := h.fetchOwnedNote(c)
	if !ok {
		return
	}

	if err := h.repo.SoftDelete(c.Request.Context(), n.ID); err != nil {
		c.JSON(http.StatusInternalServerError, apicommon.Response[any]{Error: "internal_error"})
		return
	}

	c.JSON(http.StatusOK, apicommon.Response[any]{Message: "note deleted"})
}

// fetchOwnedNote parses the UUID param, loads the note, and verifies ownership.
func (h *Handler) fetchOwnedNote(c *gin.Context) (*note.Note, bool) {
	userID, ok := middleware.GetActorUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, apicommon.Response[any]{Error: "unauthorized"})
		return nil, false
	}

	noteUUID, err := uuid.Parse(c.Param("uuid"))
	if err != nil {
		c.JSON(http.StatusBadRequest, apicommon.Response[any]{Error: "invalid_uuid"})
		return nil, false
	}

	n, err := h.repo.GetByUUID(c.Request.Context(), noteUUID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, apicommon.Response[any]{Error: "note_not_found"})
		} else {
			c.JSON(http.StatusInternalServerError, apicommon.Response[any]{Error: "internal_error"})
		}
		return nil, false
	}

	if n.UserID != userID {
		c.JSON(http.StatusForbidden, apicommon.Response[any]{Error: "forbidden"})
		return nil, false
	}

	return n, true
}
