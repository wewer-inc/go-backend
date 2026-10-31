package users

import (
	"net/http"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/gin-gonic/gin"
)

// Handler serves account management.
type Handler struct {
	svc *Service
}

// NewHandler returns a Handler that delegates to svc.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// ChangeRole handles a request to move a user to a new role.
func (h *Handler) ChangeRole(c *gin.Context) {
	var req ChangeRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apicommon.RespondBindError(c, err)
		return
	}
	s, ok := middleware.GetActorSubject(c)
	if !ok {
		apicommon.RespondError(c, apierr.Unauthorized("unauthorized"))
		return
	}
	resp, err := h.svc.ChangeRole(c.Request.Context(), s, c.Param("uuid"), req.Role, c.ClientIP())
	if err != nil {
		apicommon.RespondError(c, err)
		return
	}
	c.JSON(http.StatusOK, apicommon.Response[RoleResponse]{Data: resp})
}
