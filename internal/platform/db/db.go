package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/dbstats"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/pgdialect"
	"github.com/rs/zerolog"
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
	LogQueryValues  bool          // DB_LOG_QUERY_VALUES logs parameter values in slow and failed query logs. Keep false wherever real personal data exists.
}

// Start opens the DB, configures the connection pool, pings, and runs migrations if enabled.
func Start(ctx context.Context, cfg Config, log zerolog.Logger) (*gorm.DB, error) {
	// Opening through pgdialect is what lets a connection survive a migration that alters
	// a table. Its package comment explains why, and should be read before this changes.
	gdb, err := gorm.Open(pgdialect.Open(cfg.DSN), &gorm.Config{
		Logger:                                   newGormLogger(cfg, log),
		DisableForeignKeyConstraintWhenMigrating: true,
	})

	if err != nil {
		return nil, fmt.Errorf("db open: %w", err)
	}

	registerQueryTiming(gdb)

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

// registerQueryTiming surrounds each kind of GORM operation with a pair of callbacks that
// time it and add the result to the dbstats.Stats on the statement's context. Where the
// context has no Stats (a worker, a migration, a health ping) recording does nothing. The
// callbacks read the clock and never look at rows or parameters.
func registerQueryTiming(gdb *gorm.DB) {
	const startedAt = "dbstats:start"
	stamp := func(tx *gorm.DB) { tx.InstanceSet(startedAt, time.Now()) }
	record := func(tx *gorm.DB) {
		v, _ := tx.InstanceGet(startedAt)
		if began, ok := v.(time.Time); ok {
			dbstats.FromContext(tx.Statement.Context).Record(time.Since(began))
		}
	}

	c := gdb.Callback()
	operations := []struct {
		name          string
		before, after func(string, func(*gorm.DB)) error
	}{
		{"create", c.Create().Before("gorm:create").Register, c.Create().After("gorm:create").Register},
		{"query", c.Query().Before("gorm:query").Register, c.Query().After("gorm:query").Register},
		{"update", c.Update().Before("gorm:update").Register, c.Update().After("gorm:update").Register},
		{"delete", c.Delete().Before("gorm:delete").Register, c.Delete().After("gorm:delete").Register},
		{"row", c.Row().Before("gorm:row").Register, c.Row().After("gorm:row").Register},
		{"raw", c.Raw().Before("gorm:raw").Register, c.Raw().After("gorm:raw").Register},
	}
	// Register fails only when a callback name is already taken. Every name built here is
	// distinct, so there is no error worth handling.
	for _, op := range operations {
		_ = op.before("dbstats:before_"+op.name, stamp)
		_ = op.after("dbstats:after_"+op.name, record)
	}
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

// PoolStatsFields adds database/sql's view of the pool to an event as a "db_pool" object,
// giving each heartbeat a record of how the pool is doing. wait_count and the closed_*
// values only ever grow, so read them by comparing beats: a climbing closed_max_idle means
// connections are being opened and thrown away, and a climbing wait_count means callers
// had to queue for one.
func PoolStatsFields(gdb *gorm.DB) func(*zerolog.Event) {
	return func(e *zerolog.Event) {
		if pool := connectionPool(gdb); pool != nil {
			e.Dict("db_pool", poolCounters(pool.Stats()))
		}
	}
}

func connectionPool(gdb *gorm.DB) *sql.DB {
	if gdb == nil {
		return nil
	}
	pool, err := gdb.DB()
	if err != nil {
		return nil
	}
	return pool
}

func poolCounters(stats sql.DBStats) *zerolog.Event {
	dict := zerolog.Dict()
	for _, counter := range []struct {
		key   string
		value int64
	}{
		{"max_open", int64(stats.MaxOpenConnections)},
		{"open", int64(stats.OpenConnections)},
		{"in_use", int64(stats.InUse)},
		{"idle", int64(stats.Idle)},
		{"wait_count", stats.WaitCount},
		{"wait_ms", stats.WaitDuration.Milliseconds()},
		{"closed_max_idle", stats.MaxIdleClosed},
		{"closed_idle_time", stats.MaxIdleTimeClosed},
		{"closed_lifetime", stats.MaxLifetimeClosed},
	} {
		dict = dict.Int64(counter.key, counter.value)
	}
	return dict
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

// newGormLogger builds the SQL log. Failed and slow statements go to zerolog showing
// placeholders instead of parameter values, unless cfg.LogQueryValues opts in, and an error
// marked as expected on the context produces no line. The placeholders matter because slow
// statements log at a level production keeps, so their values would otherwise put personal
// data in the logs.
func newGormLogger(cfg Config, log zerolog.Logger) glogger.Interface {
	return expectingLogger{Interface: glogger.New(
		zerologGormWriter{log: log},
		glogger.Config{
			SlowThreshold:             cfg.SlowThreshold,
			LogLevel:                  glogger.Warn,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
			ParameterizedQueries:      !cfg.LogQueryValues,
		},
	)}
}

// zerolog adapter for GORM.
type zerologGormWriter struct{ log zerolog.Logger }

func (w zerologGormWriter) Printf(format string, args ...interface{}) {
	w.log.Warn().Msgf(format, args...)
}
