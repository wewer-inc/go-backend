//go:build integration

package db

import (
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/pgtest"
	"github.com/rs/zerolog"
)

// Every migration must apply to an empty database, roll back, and apply again.
func TestMigrationsApplyAndRollBackCleanly(t *testing.T) {
	db := pgtest.Open(t)
	log := zerolog.Nop()
	if err := UpMigrations(db, log); err != nil {
		t.Fatalf("up: %v", err)
	}
	for range migrations() {
		if err := DownMigrations(db, log); err != nil {
			t.Fatalf("down: %v", err)
		}
	}
	if err := UpMigrations(db, log); err != nil {
		t.Fatalf("up again: %v", err)
	}
}
