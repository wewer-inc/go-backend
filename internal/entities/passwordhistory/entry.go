// Package passwordhistory records previously used password hashes, to refuse reuse.
package passwordhistory

import "gorm.io/gorm"

// Entry stores one of a user's former password hashes. A password change deletes whatever
// exceeds the configured count, so a user never has more than a handful of rows here.
type Entry struct {
	gorm.Model
	UserID       uint   `gorm:"not null;index"     json:"user_id"`
	PasswordHash string `gorm:"type:text;not null" json:"-"`
}

func (Entry) TableName() string { return "password_history" }
