package user

import (
	"time"

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

	// The TOTP secret, encrypted at rest. MFAEnrolledAt being set is what turns MFA on; the
	// pending pair holds a secret awaiting its first code.
	TOTPSecretEnc       string     `gorm:"column:totp_secret_enc;type:text"        json:"-"`
	MFAEnrolledAt       *time.Time `gorm:"column:mfa_enrolled_at"                  json:"-"`
	MFAPendingSecretEnc string     `gorm:"column:mfa_pending_secret_enc;type:text" json:"-"`
	MFAPendingAt        *time.Time `gorm:"column:mfa_pending_at"                   json:"-"`
}

func (User) TableName() string { return "users" }
