package user

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	UUID         uuid.UUID     `gorm:"type:uuid;default:uuid_generate_v4();uniqueIndex" json:"uuid"`
	Email        string        `gorm:"type:citext;uniqueIndex;not null"                 json:"email"`
	PasswordHash string        `gorm:"type:text"                                        json:"-"`
	Name         string        `gorm:"type:text;not null"                               json:"name"`
	PlatformRole entities.Role `gorm:"type:text;not null;default:'user'"                json:"platform_role"`
	GoogleID     string        `gorm:"type:text;index"                                  json:"-"`
	AvatarURL    string        `gorm:"type:text"                                        json:"avatar_url,omitempty"`
}

func (User) TableName() string { return "users" }
