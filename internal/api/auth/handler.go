package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/gin-gonic/gin"
)

const oauthStateCookie = "oauth_state"

type Handler struct {
	svc    *Service
	secure bool // set cookies with the Secure flag (prod / TLS)
}

func NewHandler(svc *Service, secureCookies bool) *Handler {
	return &Handler{svc: svc, secure: secureCookies}
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apicommon.RespondBindError(c, err)
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
		apicommon.RespondBindError(c, err)
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
		apicommon.RespondBindError(c, err)
		return
	}

	resp, err := h.svc.RefreshTokens(c.Request.Context(), req.RefreshToken)
	if err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusOK, apicommon.Response[AuthResponse]{Data: resp})
}

// Logout revokes the caller's access token and (optionally) a supplied refresh
// session. It is mounted on the authenticated routes, so the access claims are
// already present in context.
func (h *Handler) Logout(c *gin.Context) {
	var req LogoutRequest
	// Body is optional; ignore bind errors and fall back to access-token-only revocation.
	_ = c.ShouldBindJSON(&req)

	claims, _ := middleware.GetActorClaims(c)
	if err := h.svc.Logout(c.Request.Context(), claims, req.RefreshToken); err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusOK, apicommon.Response[any]{Message: "logged out"})
}

func (h *Handler) GoogleRedirect(c *gin.Context) {
	// Generate a random state, stash it in an HttpOnly cookie, and echo it in
	// the OAuth state param. The callback compares the two (double-submit) to
	// defend against login-CSRF.
	state, err := randomState()
	if err != nil {
		respondError(c, apierr.Internal("failed to generate oauth state"))
		return
	}

	url, err := h.svc.GoogleAuthURL(state)
	if err != nil {
		respondError(c, err)
		return
	}

	// 10-minute lifetime is plenty for the redirect round-trip.
	c.SetCookie(oauthStateCookie, state, 600, "/v1/auth", "", h.secure, true)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *Handler) GoogleCallback(c *gin.Context) {
	state := c.Query("state")
	cookieState, err := c.Cookie(oauthStateCookie)
	if err != nil || state == "" || state != cookieState {
		respondError(c, apierr.BadRequest("invalid_state", "oauth state mismatch"))
		return
	}
	// One-time use: clear the cookie regardless of outcome.
	c.SetCookie(oauthStateCookie, "", -1, "/v1/auth", "", h.secure, true)

	code := c.Query("code")
	if code == "" {
		respondError(c, apierr.BadRequest("missing_code", "missing code parameter"))
		return
	}

	resp, err := h.svc.GoogleCallback(c.Request.Context(), code)
	if err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusOK, apicommon.Response[AuthResponse]{Data: resp})
}

// randomState returns a cryptographically-random hex string for OAuth state.
func randomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// respondError maps *apierr.APIError to its HTTP status, falls back to 500.
func respondError(c *gin.Context, err error) {
	// Attaching the error lets the request logger record the cause under its request_id.
	// Only the code, message and details go into the response.
	_ = c.Error(err)
	var apiErr *apierr.APIError
	if errors.As(err, &apiErr) {
		c.JSON(apiErr.Status, apicommon.Response[any]{Error: apiErr.Code, Message: apiErr.Message, Details: apiErr.Details})
		return
	}
	c.JSON(http.StatusInternalServerError, apicommon.Response[any]{Error: "internal_error"})
}
