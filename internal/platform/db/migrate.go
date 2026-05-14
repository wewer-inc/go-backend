package db

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/note"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

func UpMigrations(gdb *gorm.DB, log zerolog.Logger) error {
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
	}
}
