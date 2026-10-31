package db

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/loginfailure"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/mfa"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/note"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/passwordhistory"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/passwordreset"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

func UpMigrations(gdb *gorm.DB, _ zerolog.Logger) error {
	m := gormigrate.New(gdb, gormigrate.DefaultOptions, migrations())
	return m.Migrate()
}

func DownMigrations(gdb *gorm.DB, _ zerolog.Logger) error {
	m := gormigrate.New(gdb, gormigrate.DefaultOptions, migrations())
	return m.RollbackLast()
}

func migrations() []*gormigrate.Migration {
	return []*gormigrate.Migration{
		{
			ID: "0001_init",
			Migrate: func(tx *gorm.DB) error {
				if err := tx.Exec(`CREATE EXTENSION IF NOT EXISTS citext`).Error; err != nil {
					return err
				}
				if err := tx.Exec(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp"`).Error; err != nil {
					return err
				}
				return tx.AutoMigrate(&user.User{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable(&user.User{})
			},
		},
		{
			ID: "0002_notes",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&note.Note{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable(&note.Note{})
			},
		},
		{
			ID: "0003_audit_logs",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&audit.Log{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable(&audit.Log{})
			},
		},
		{
			ID: "0004_sessions",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&session.Session{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable(&session.Session{})
			},
		},
		{
			ID: "0005_password_recovery",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&passwordreset.Token{}, &passwordhistory.Entry{}, &loginfailure.Failure{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable(&passwordreset.Token{}, &passwordhistory.Entry{}, &loginfailure.Failure{})
			},
		},
		{
			ID: "0006_session_refresh_tokens",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&session.RetiredRefreshToken{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable(&session.RetiredRefreshToken{})
			},
		},
		{
			ID: "0007_mfa",
			Migrate: func(tx *gorm.DB) error {
				if err := tx.AutoMigrate(&mfa.BackupCode{}, &mfa.Challenge{}); err != nil {
					return err
				}
				// 0001 applies whatever the User struct looks like today, so on a new database
				// these columns are there before this step runs and on an older one they are not.
				// As SQL with IF NOT EXISTS, the step adds exactly these columns and suits both.
				return tx.Exec(`ALTER TABLE users
					ADD COLUMN IF NOT EXISTS totp_secret_enc text,
					ADD COLUMN IF NOT EXISTS mfa_enrolled_at timestamptz,
					ADD COLUMN IF NOT EXISTS mfa_pending_secret_enc text,
					ADD COLUMN IF NOT EXISTS mfa_pending_at timestamptz`).Error
			},
			Rollback: func(tx *gorm.DB) error {
				if err := tx.Exec(`ALTER TABLE users
					DROP COLUMN IF EXISTS totp_secret_enc,
					DROP COLUMN IF EXISTS mfa_enrolled_at,
					DROP COLUMN IF EXISTS mfa_pending_secret_enc,
					DROP COLUMN IF EXISTS mfa_pending_at`).Error; err != nil {
					return err
				}
				return tx.Migrator().DropTable(&mfa.BackupCode{}, &mfa.Challenge{})
			},
		},
		{
			ID: "0008_totp_last_step",
			Migrate: func(tx *gorm.DB) error {
				return tx.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step bigint`).Error
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Exec(`ALTER TABLE users DROP COLUMN IF EXISTS totp_last_step`).Error
			},
		},
	}
}
