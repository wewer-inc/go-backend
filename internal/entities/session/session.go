// Package session holds the server-side authentication session.
package session

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// LoginMethod records which sign-in path created a session.
type LoginMethod string

const (
	MethodPassword LoginMethod = "password"
	MethodGoogle   LoginMethod = "google"
)

// Session is one signed-in device. Its UUID travels as the access token's sid claim. Its
// refresh token is opaque and only the SHA-256 hash is stored, so a database dump yields
// nothing usable.
//
// A session is one token family: rotation updates this row rather than adding one, and
// PrevRefreshTokenHash remembers the generation before, which is how a replay is spotted.
// Replaying a token older than that matches no row and is simply refused.
type Session struct {
	gorm.Model
	UUID                 uuid.UUID   `gorm:"type:uuid;uniqueIndex;not null" json:"uuid"`
	UserID               uint        `gorm:"not null;index"                 json:"user_id"`
	RefreshTokenHash     string      `gorm:"type:text;not null;index"       json:"-"`
	PrevRefreshTokenHash string      `gorm:"type:text;index"                json:"-"`
	LoginMethod          LoginMethod `gorm:"type:text;not null"             json:"login_method"`
	// ImpersonatorUserID points at the admin behind a "login as" session and stays nil after
	// a normal sign-in. The token has it too, but the row lets refresh turn the session away
	// and the owner's session list flag it, and it is still there once the token has expired.
	ImpersonatorUserID *uint     `gorm:"index"     json:"impersonator_user_id,omitempty"`
	UserAgent          string    `gorm:"type:text" json:"user_agent"`
	IP                 string    `gorm:"type:text" json:"ip"`
	LastUsedAt         time.Time `json:"last_used_at"`
	// RotatedAt is the only way to separate a racing refresh from a replay, since each comes
	// with the previous token and only the time since rotation differs. A nil value counts
	// as old, so doubt resolves toward revoking.
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
	// ExpiresAt is the refresh token's expiry, pushed out by each rotation up to
	// AbsoluteExpiry, which never moves.
	ExpiresAt      time.Time  `json:"expires_at"`
	AbsoluteExpiry time.Time  `json:"absolute_expiry"`
	RevokedAt      *time.Time `gorm:"index" json:"revoked_at,omitempty"`
}

func (Session) TableName() string { return "sessions" }
