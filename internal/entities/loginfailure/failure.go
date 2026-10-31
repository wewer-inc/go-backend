// Package loginfailure holds the counter behind login lockout.
package loginfailure

import "time"

// Failure counts failed sign-ins for one email address within a window. It is keyed on
// the address rather than a user so an unknown address locks out like a known one, which
// keeps lockout from revealing who has an account. The key is a hash because this table
// fills with whatever strangers type.
type Failure struct {
	KeyHash     string    `gorm:"primaryKey;type:text"`
	Failures    int       `gorm:"not null"`
	WindowStart time.Time `gorm:"not null;index"`
}

func (Failure) TableName() string { return "login_failures" }
