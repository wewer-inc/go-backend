package auth

import (
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
)

// RegisterRequest leaves the password's length to platformauth.ValidatePassword, the one
// place the policy is defined. The binder's max counts characters, not the bytes bcrypt
// is limited by.
type RegisterRequest struct {
	Name     string `json:"name"     binding:"required"`
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// ChangePasswordRequest changes the caller's own password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password"     binding:"required"`
}

// ForgotPasswordRequest asks for a reset link.
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

// ResetPasswordRequest carries the token from a reset email and the password to set.
type ResetPasswordRequest struct {
	Token       string `json:"token"        binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type LoginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type LogoutRequest struct {
	// Optional: when provided, this refresh session is also revoked.
	RefreshToken string `json:"refresh_token"`
}

type TokenPairResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type UserResponse struct {
	UUID         string `json:"uuid"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	AvatarURL    string `json:"avatar_url,omitempty"`
	PlatformRole string `json:"platform_role"`
}

type AuthResponse struct {
	User   UserResponse      `json:"user"`
	Tokens TokenPairResponse `json:"tokens"`
}

// PermissionsResponse is what GET /v1/auth/permissions serves.
type PermissionsResponse struct {
	Role         entities.Role             `json:"role"`
	Permissions  []authz.Permission        `json:"permissions"`
	Capabilities []authz.Capability        `json:"capabilities"`
	Scopes       map[authz.Resource]string `json:"scopes"`
}

// SessionView is a session as shown to the user who owns it. Hashes never leave the
// server.
type SessionView struct {
	UUID         string    `json:"uuid"`
	Current      bool      `json:"current"`
	LoginMethod  string    `json:"login_method"`
	UserAgent    string    `json:"user_agent"`
	IP           string    `json:"ip"`
	CreatedAt    time.Time `json:"created_at"`
	LastUsedAt   time.Time `json:"last_used_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Impersonated bool      `json:"impersonated"`
}

func toSessionView(row *session.Session, currentSID string) SessionView {
	id := row.UUID.String()
	return SessionView{
		UUID:         id,
		Current:      id == currentSID,
		LoginMethod:  string(row.LoginMethod),
		UserAgent:    row.UserAgent,
		IP:           row.IP,
		CreatedAt:    row.CreatedAt,
		LastUsedAt:   row.LastUsedAt,
		ExpiresAt:    row.AbsoluteExpiry,
		Impersonated: row.ImpersonatorUserID != nil,
	}
}
