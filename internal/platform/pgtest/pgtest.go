//go:build integration

// Package pgtest gives an integration test a throwaway Postgres database, so tests do
// not see each other's rows and a failed run leaves nothing to clean up by hand.
package pgtest

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/pgdialect"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Open creates a database, returns a handle to it, and drops it when the test ends. It
// skips the test when TEST_DATABASE_URL is not set.
func Open(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	admin, err := gorm.Open(pgdialect.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	name := "t_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := admin.Exec(`CREATE DATABASE ` + name).Error; err != nil {
		t.Fatal(err)
	}

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := gorm.Open(pgdialect.Open(u.String()), &gorm.Config{
		Logger:                                   logger.Default.LogMode(logger.Silent),
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		if err := admin.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, name)).Error; err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
		if sqlDB, err := admin.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}
