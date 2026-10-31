// Package passwordreset holds the single-use credential behind forgot-password.
package passwordreset

import (
	"time"

	"gorm.io/gorm"
)

// Token is delivered only through the emailed link. Only its SHA-256 hash is stored, so
// reading this table does not let anyone reset a password.
type Token struct {
	gorm.Model
	UserID     uint       `gorm:"not null;index"                 json:"user_id"`
	TokenHash  string     `gorm:"type:text;not null;uniqueIndex" json:"-"`
	ExpiresAt  time.Time  `gorm:"not null"                       json:"expires_at"`
	ConsumedAt *time.Time `gorm:"index"                          json:"consumed_at,omitempty"`
	RequestIP  string     `gorm:"type:text"                      json:"-"`
}

func (Token) TableName() string { return "password_reset_tokens" }
