package auth

import (
	"errors"
	"net/http"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apicommon.Response[any]{Error: err.Error()})
		return
	}

	resp, err := h.svc.Register(c.Request.Context(), req)
	if err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusCreated, apicommon.Response[AuthResponse]{Data: resp})
}

func (h *Handler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apicommon.Response[any]{Error: err.Error()})
		return
	}

	resp, err := h.svc.Login(c.Request.Context(), req)
	if err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusOK, apicommon.Response[AuthResponse]{Data: resp})
}

func (h *Handler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, apicommon.Response[any]{Error: err.Error()})
		return
	}

	resp, err := h.svc.RefreshTokens(c.Request.Context(), req.RefreshToken)
	if err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusOK, apicommon.Response[AuthResponse]{Data: resp})
}

func (h *Handler) GoogleRedirect(c *gin.Context) {
	// state should be a random value the client verifies on callback (CSRF protection)
	state := c.Query("state")
	if state == "" {
		state = "default"
	}

	url, err := h.svc.GoogleAuthURL(state)
	if err != nil {
		respondError(c, err)
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *Handler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, apicommon.Response[any]{Error: "missing code parameter"})
		return
	}

	resp, err := h.svc.GoogleCallback(c.Request.Context(), code)
	if err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusOK, apicommon.Response[AuthResponse]{Data: resp})
}

// respondError maps *apierr.APIError to its HTTP status, falls back to 500.
func respondError(c *gin.Context, err error) {
	var apiErr *apierr.APIError
	if errors.As(err, &apiErr) {
		c.JSON(apiErr.Status, apicommon.Response[any]{Error: apiErr.Code, Message: apiErr.Message})
		return
	}
	c.JSON(http.StatusInternalServerError, apicommon.Response[any]{Error: "internal_error"})
}
