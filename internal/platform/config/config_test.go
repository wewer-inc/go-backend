package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
)

func TestLoad_ParsesDBConfig(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("DB_DSN", "postgres://user:pass@localhost:5432/db?sslmode=disable")
	t.Setenv("DB_MIGRATE_ON_START", "true")
	t.Setenv("DB_MAX_OPEN", "20")
	t.Setenv("DB_MAX_IDLE", "10")
	t.Setenv("DB_CONN_LIFETIME", "30m")
	t.Setenv("DB_CONN_IDLE_TIME", "5m")
	t.Setenv("DB_SLOW_THRESHOLD", "150ms")

	cfg := config.Load()

	if cfg.DB_DSN != os.Getenv("DB_DSN") {
		t.Errorf("expected DB_DSN %s, got %s", os.Getenv("DB_DSN"), cfg.DB_DSN)
	}

	if !cfg.DB_MIGRATE_ON_START {
		t.Errorf("expected DB_MIGRATE_ON_START to be true, got false")
	}

	if cfg.DB_MAX_OPEN != 20 {
		t.Errorf("expected DB_MAX_OPEN 20, got %d", cfg.DB_MAX_OPEN)
	}

	if cfg.DB_MAX_IDLE != 10 {
		t.Errorf("expected DB_MAX_IDLE 10, got %d", cfg.DB_MAX_IDLE)
	}

	if cfg.DB_CONN_LIFETIME != 30*time.Minute {
		t.Errorf("expected DB_CONN_LIFETIME 30m0s, got %s", cfg.DB_CONN_LIFETIME)
	}

	if cfg.DB_CONN_IDLE_TIME != 5*time.Minute {
		t.Errorf("expected DB_CONN_IDLE_TIME 5m0s, got %s", cfg.DB_CONN_IDLE_TIME)
	}

	if cfg.DB_SLOW_THRESHOLD != 150*time.Millisecond {
		t.Errorf("expected DB_SLOW_THRESHOLD 150ms, got %s", cfg.DB_SLOW_THRESHOLD)
	}
}
