// Package mfa holds the rows behind TOTP sign-in: challenges and backup codes.
package mfa

import (
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"gorm.io/gorm"
)

// BackupCode is a one-time way back into an account. The plaintext is displayed once at
// generation, and this table keeps nothing but its SHA-256 hash.
type BackupCode struct {
	gorm.Model
	UserID   uint       `gorm:"not null;index"           json:"user_id"`
	CodeHash string     `gorm:"type:text;not null;index" json:"-"`
	UsedAt   *time.Time `json:"used_at,omitempty"`
}

func (BackupCode) TableName() string { return "mfa_backup_codes" }

// Challenge is the step between a good first factor and a session. Its token proves only
// that the first factor passed, and is opaque rather than a JWT so nothing can mistake it
// for an access token. It lives in Postgres so MFA works with Redis disabled.
type Challenge struct {
	gorm.Model
	UserID    uint   `gorm:"not null;index"                 json:"user_id"`
	TokenHash string `gorm:"type:text;not null;uniqueIndex" json:"-"`
	// Method is how the first factor passed, carried onto the session.
	Method     session.LoginMethod `gorm:"type:text;not null" json:"method"`
	Attempts   int                 `gorm:"not null;default:0" json:"attempts"`
	ExpiresAt  time.Time           `gorm:"not null"           json:"expires_at"`
	ConsumedAt *time.Time          `json:"consumed_at,omitempty"`
}

func (Challenge) TableName() string { return "mfa_challenges" }
