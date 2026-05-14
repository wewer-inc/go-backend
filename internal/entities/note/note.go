package note

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Note is the example entity — copy-paste this as a starting point for new features.
type Note struct {
	gorm.Model
	UUID   uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();uniqueIndex" json:"uuid"`
	UserID uint      `gorm:"not null;index"                                   json:"user_id"`
	Title  string    `gorm:"type:text;not null"                               json:"title"`
	Body   string    `gorm:"type:text"                                        json:"body"`
}

func (Note) TableName() string { return "notes" }
