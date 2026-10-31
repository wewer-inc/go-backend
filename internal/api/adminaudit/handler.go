// Package adminaudit serves the audit trail to those allowed to read it.
package adminaudit

import (
	"net/http"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Handler struct {
	repo repo.Repo[audit.Log]
	db   *gorm.DB
}

func NewHandler(r repo.Repo[audit.Log], db *gorm.DB) *Handler {
	return &Handler{repo: r, db: db}
}

// List serves the trail newest first.
func (h *Handler) List(c *gin.Context) {
	var req ListRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		apicommon.RespondError(c, apierr.BadRequest("invalid_query", "query parameters are not valid"))
		return
	}

	filters := map[string]any{}
	if req.Event != "" {
		filters["event"] = req.Event
	}
	if req.ActorUserID != 0 {
		filters["actor_user_id"] = req.ActorUserID
	}
	if req.ImpersonatorUserID != 0 {
		filters["impersonator_user_id"] = req.ImpersonatorUserID
	}

	rows, page, err := h.repo.List(c.Request.Context(), store.QueryOpts{
		Filters:  filters,
		Sort:     []store.SortField{{Field: "id", Desc: true}},
		Page:     req.Page,
		PageSize: req.PageSize,
	})
	if err != nil {
		apicommon.RespondError(c, apierr.InternalErr(err, "failed to list audit records"))
		return
	}

	items := make([]LogResponse, len(rows))
	for i := range rows {
		items[i] = toLogResponse(&rows[i])
	}
	c.JSON(http.StatusOK, apicommon.PaginatedResponse[LogResponse]{
		Data: items,
		Page: &apicommon.Pagination{Page: page.Page, PageSize: page.PageSize, Total: page.Total, HasNext: page.HasNext},
	})
}

// Verify walks the stored chain, against a trusted checkpoint when one is given. It is
// linear in the table's size, so on a large trail it can outlast the server's write
// timeout; run auditlog.VerifyStored from a job there.
func (h *Handler) Verify(c *gin.Context) {
	var req VerifyRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		apicommon.RespondError(c, apierr.BadRequest("invalid_query", "query parameters are not valid"))
		return
	}
	var checkpoint *auditlog.Checkpoint
	if req.CheckpointID != 0 {
		checkpoint = &auditlog.Checkpoint{ID: req.CheckpointID, Hash: req.CheckpointHash}
	}

	res, err := auditlog.VerifyStored(c.Request.Context(), h.db, checkpoint)
	if err != nil {
		apicommon.RespondError(c, apierr.InternalErr(err, "failed to verify the audit chain"))
		return
	}
	c.JSON(http.StatusOK, apicommon.Response[auditlog.VerifyResult]{Data: &res})
}
