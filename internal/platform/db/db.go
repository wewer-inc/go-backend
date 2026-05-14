package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
)

// Config to map env vars and configure the database connection.
type Config struct {
	DSN             string        // DB_DSN is the Data Source Name for connecting to the database.
	MigrateOnStart  bool          // DB_MIGRATE_ON_START indicates whether to run migrations on application start.
	MaxOpen         int           // DB_MAX_OPEN is the maximum number of open connections to the database.
	MaxIdle         int           // DB_MAX_IDLE is the maximum number of idle connections in the pool.
	ConnMaxLifetime time.Duration // DB_CONN_MAX_LIFETIME is the maximum amount of time a connection may be reused.
	ConnMaxIdleTime time.Duration // DB_CONN_MAX_IDLE_TIME is the maximum amount of time a connection may be idle.
	SlowThreshold   time.Duration // DB_SLOW_THRESHOLD is the threshold in milliseconds for logging slow queries.
}

// Start opens the DB, configures the connection pool, pings, and runs migrations if enabled.
func Start(ctx context.Context, cfg Config, log zerolog.Logger) (*gorm.DB, error) {
	gormLog := glogger.New(
		zerologGormWriter{log: log},
		glogger.Config{
			SlowThreshold:             cfg.SlowThreshold,
			LogLevel:                  glogger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	gdb, err := gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{
		Logger:                                   gormLog,
		DisableForeignKeyConstraintWhenMigrating: true,
	})

	if err != nil {
		return nil, fmt.Errorf("db open: %w", err)
	}

	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, fmt.Errorf("db unwrap: %w", err)
	}

	// Pooling
	if cfg.MaxOpen > 0 {
		sqlDB.SetMaxOpenConns(cfg.MaxOpen)
	}
	if cfg.MaxIdle > 0 {
		sqlDB.SetMaxIdleConns(cfg.MaxIdle)
	}
	if cfg.ConnMaxLifetime > 0 {
		sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}
	if cfg.ConnMaxIdleTime > 0 {
		sqlDB.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	}

	// Fail-fast ping if we can't connect to the database.
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(pctx); err != nil {
		return nil, fmt.Errorf("db ping: %w", err)
	}

	log.Info().
		Str("component", "db").
		Str("driver", "postgres").
		Int("max_open", cfg.MaxOpen).
		Int("max_idle", cfg.MaxIdle).
		Dur("conn_lifetime", cfg.ConnMaxLifetime).
		Dur("conn_idle_time", cfg.ConnMaxIdleTime).
		Dur("slow_threshold", cfg.SlowThreshold).
		Msg("database connected")

	if cfg.MigrateOnStart {
		log.Info().Str("component", "db").Msg("running migration (up)")
		if err := UpMigrations(gdb, log); err != nil {
			return nil, fmt.Errorf("migrations up: %w", err)
		}
		log.Info().Str("component", "db").Msg("migration complete")
	}

	return gdb, nil
}

// ReadyCheck pings with a timeout; used by /ready
func ReadyCheck(ctx context.Context, gdb *gorm.DB, timeout time.Duration) error {
	sqlDB, err := gdb.DB()
	if err != nil {
		return fmt.Errorf("db unwrap: %w", err)
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	return sqlDB.PingContext(ctx)
}

// Stop closes the underlying database connection.
func Stop(gdb *gorm.DB) error {
	sqlDB, err := gdb.DB()
	if err != nil {
		return fmt.Errorf("db unwrap: %w", err)
	}
	return sqlDB.Close()
}

// SQLDB exposes *sql.DB if needed by callers. Be CAREFUL to not close it.
func SQLDB(gdb *gorm.DB) (*sql.DB, error) { return gdb.DB() }

// zerolog adapter for GORM.
type zerologGormWriter struct{ log zerolog.Logger }

func (w zerologGormWriter) Printf(format string, args ...interface{}) {
	w.log.Warn().Msgf(format, args...)
}
