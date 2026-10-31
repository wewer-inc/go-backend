package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
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

func loginContext(c *gin.Context) LoginContext {
	ua := c.Request.UserAgent()
	if len(ua) > maxUserAgentLen {
		ua = ua[:maxUserAgentLen]
	}
	return LoginContext{UserAgent: ua, IP: c.ClientIP()}
}

func (h *Handler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apicommon.RespondBindError(c, err)
		return
	}

	resp, err := h.svc.Register(c.Request.Context(), req, loginContext(c))
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

	resp, err := h.svc.Login(c.Request.Context(), req, loginContext(c))
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

	resp, err := h.svc.RefreshTokens(c.Request.Context(), req.RefreshToken, loginContext(c))
	if err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusOK, apicommon.Response[AuthResponse]{Data: resp})
}

// Logout revokes the caller's session and (optionally) a supplied refresh session. It is
// mounted on the authenticated routes, so the access claims are already in context.
func (h *Handler) Logout(c *gin.Context) {
	var req LogoutRequest
	// Body is optional; ignore bind errors and fall back to the current session only.
	_ = c.ShouldBindJSON(&req)

	claims, _ := middleware.GetActorClaims(c)
	userID, _ := middleware.GetActorUserID(c)
	if err := h.svc.Logout(c.Request.Context(), userID, claims, req.RefreshToken, c.ClientIP()); err != nil {
		respondError(c, err)
		return
	}

	c.JSON(http.StatusOK, apicommon.Response[any]{Message: "logged out"})
}

// ChangePassword changes the caller's password.
func (h *Handler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apicommon.RespondBindError(c, err)
		return
	}
	userID, _ := middleware.GetActorUserID(c)
	claims, _ := middleware.GetActorClaims(c)
	if err := h.svc.ChangePassword(c.Request.Context(), userID, claims.SID, req, c.ClientIP()); err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, apicommon.Response[any]{Message: "password changed"})
}

// ForgotPassword always answers the same way for a well-formed address, known or not. A
// malformed one is refused, which says something about the request and nothing about any
// account.
func (h *Handler) ForgotPassword(c *gin.Context) {
	var req ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apicommon.RespondBindError(c, err)
		return
	}
	h.svc.RequestPasswordReset(req.Email, loginContext(c))
	c.JSON(http.StatusOK, apicommon.Response[any]{Message: "if that address has an account, a reset link is on its way"})
}

// ResetPassword redeems an emailed reset token.
func (h *Handler) ResetPassword(c *gin.Context) {
	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apicommon.RespondBindError(c, err)
		return
	}
	if err := h.svc.ResetPassword(c.Request.Context(), req, loginContext(c)); err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, apicommon.Response[any]{Message: "password reset"})
}

// ListSessions serves the caller's live sessions.
func (h *Handler) ListSessions(c *gin.Context) {
	userID, _ := middleware.GetActorUserID(c)
	claims, _ := middleware.GetActorClaims(c)
	views, err := h.svc.ListSessions(c.Request.Context(), userID, claims.SID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, apicommon.Response[[]SessionView]{Data: &views})
}

// RevokeSession ends the session named by the sid path parameter.
func (h *Handler) RevokeSession(c *gin.Context) {
	userID, _ := middleware.GetActorUserID(c)
	if err := h.svc.RevokeSession(c.Request.Context(), userID, c.Param("sid"), c.ClientIP()); err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, apicommon.Response[any]{Message: "session revoked"})
}

// RevokeOtherSessions signs the caller out everywhere but this session.
func (h *Handler) RevokeOtherSessions(c *gin.Context) {
	userID, _ := middleware.GetActorUserID(c)
	claims, _ := middleware.GetActorClaims(c)
	if err := h.svc.RevokeOtherSessions(c.Request.Context(), userID, claims.SID, c.ClientIP()); err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, apicommon.Response[any]{Message: "other sessions revoked"})
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

	resp, err := h.svc.GoogleCallback(c.Request.Context(), code, loginContext(c))
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

// Permissions serves the actor's action set so a client can show only what will work.
// It is a convenience for the interface: the server still enforces every decision.
func (h *Handler) Permissions(c *gin.Context) {
	s, ok := middleware.GetActorSubject(c)
	if !ok {
		respondError(c, apierr.Unauthorized("unauthorized"))
		return
	}
	resp := PermissionsResponse{
		Role:         s.Role,
		Permissions:  authz.PermissionsFor(s.Role),
		Capabilities: authz.CapabilitiesFor(s.Role),
		Scopes:       authz.ScopesFor(s.Role),
	}
	c.JSON(http.StatusOK, apicommon.Response[PermissionsResponse]{Data: &resp})
}
