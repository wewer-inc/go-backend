package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	httpserver "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/server"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	pdb "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/db"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/email"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/heartbeat"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/logger"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/objectstore"
	redisstore "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/redis"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/versioning"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/worker"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

type App struct {
	cfg          config.Config
	log          zerolog.Logger
	srv          *http.Server
	db           *gorm.DB
	ObjectStore  objectstore.Store
	Redis        *redisstore.Client
	Mailer       email.Mailer
	Worker       *worker.Worker
	workerCancel context.CancelFunc
	heartbeat    *heartbeat.Beater
}

// Build wires all dependencies and returns a ready-to-start App.
func Build(build versioning.BuildInfo) (*App, error) {
	cfg := config.Load()
	log := logger.NewLogger(cfg)

	gdb, err := pdb.Start(context.Background(), pdb.Config{
		DSN:             cfg.DB_DSN,
		MigrateOnStart:  cfg.DB_MIGRATE_ON_START,
		MaxOpen:         cfg.DB_MAX_OPEN,
		MaxIdle:         cfg.DB_MAX_IDLE,
		ConnMaxLifetime: cfg.DB_CONN_LIFETIME,
		ConnMaxIdleTime: cfg.DB_CONN_IDLE_TIME,
		SlowThreshold:   cfg.DB_SLOW_THRESHOLD,
		LogQueryValues:  cfg.DB_LOG_QUERY_VALUES,
	}, log)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	// S3 is optional: only wired when explicitly enabled.
	var s3Store objectstore.Store
	if cfg.S3Enabled {
		st, err := objectstore.NewS3Store(ctx, cfg.S3)
		if err != nil {
			return nil, err
		}
		hcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = st.HealthCheck(hcCtx)
		cancel()
		if err != nil {
			log.Error().Err(err).Msg("s3: health check failed")
			return nil, err
		}
		s3Store = st
	} else {
		log.Info().Msg("s3: disabled (S3_ENABLED=false)")
	}

	// Redis is optional. Rate limiting and the access-token denylist need it; auth does not.
	var redisClient *redisstore.Client
	if cfg.RedisEnabled {
		rc, err := redisstore.NewClient(cfg.Redis)
		if err != nil {
			return nil, err
		}
		redisCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
		err = rc.HealthCheck(redisCtx)
		cancel()
		if err != nil {
			log.Error().Err(err).Msg("redis: health check failed")
			return nil, err
		}
		redisClient = rc
	} else {
		log.Warn().Msg("redis: disabled (REDIS_ENABLED=false) — rate limiting is unavailable; auth endpoints run unthrottled")
	}

	// Email: real SMTP when a host is configured, noop otherwise. Production
	// must not transmit credentials in the clear.
	var mailer email.Mailer
	if cfg.SMTP.Host != "" {
		if cfg.Env == "prod" && cfg.SMTP.Mode == config.SMTPPlain {
			return nil, fmt.Errorf("smtp: plaintext mode is not allowed in prod; set SMTP_MODE=starttls or implicit_tls")
		}
		mailer = email.NewSMTPMailer(email.Config{
			Host:     cfg.SMTP.Host,
			Port:     cfg.SMTP.Port,
			From:     cfg.SMTP.From,
			Password: cfg.SMTP.Password,
			Mode:     cfg.SMTP.Mode,
		})
	} else {
		mailer = email.NewNoopMailer(log)
	}

	// Background worker: 4 goroutines, queue of 100
	w := worker.New(4, 100, log)

	deps := httpserver.Deps{
		Cfg:      cfg,
		Log:      log,
		DB:       gdb,
		ObjStore: s3Store,
		Redis:    redisClient,
		Worker:   w,
	}

	handler, err := httpserver.NewRouter(deps, build)
	if err != nil {
		return nil, err
	}

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}

	return &App{
		cfg:         cfg,
		log:         log,
		srv:         srv,
		db:          gdb,
		ObjectStore: s3Store,
		Redis:       redisClient,
		Mailer:      mailer,
		Worker:      w,
	}, nil
}

// Migrate applies database migrations and exits. Run it as a one-off task before a
// deploy, with DB_MIGRATE_ON_START=false on the service, so schema changes never race
// across request-serving instances.
func Migrate() error {
	cfg := config.Load()
	log := logger.NewLogger(cfg)
	gdb, err := pdb.Start(context.Background(), pdb.Config{
		DSN:             cfg.DB_DSN,
		MigrateOnStart:  true,
		MaxOpen:         1,
		MaxIdle:         1,
		ConnMaxLifetime: cfg.DB_CONN_LIFETIME,
		ConnMaxIdleTime: cfg.DB_CONN_IDLE_TIME,
		SlowThreshold:   cfg.DB_SLOW_THRESHOLD,
		LogQueryValues:  cfg.DB_LOG_QUERY_VALUES,
	}, log)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	log.Info().Msg("migrate: complete")
	return pdb.Stop(gdb)
}

func (a *App) Start() error {
	// Bind the listener synchronously so a bind failure (e.g. port in use) is
	// returned to the caller instead of only being logged from a goroutine.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", a.srv.Addr)
	if err != nil {
		return fmt.Errorf("http: listen %s: %w", a.srv.Addr, err)
	}
	a.log.Info().Str("addr", a.srv.Addr).Msg("http: listening")

	// Start background worker pool with an app-scoped context so in-flight jobs
	// observe shutdown via cancellation.
	workerCtx, cancel := context.WithCancel(context.Background())
	a.workerCancel = cancel
	a.Worker.Start(workerCtx)

	a.heartbeat = heartbeat.New(a.log, heartbeat.Interval).WithFields(pdb.PoolStatsFields(a.db))
	a.heartbeat.Start()

	go func() {
		if err := a.srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) && err != nil {
			a.log.Error().Err(err).Msg("http: server error")
		}
	}()
	return nil
}

func (a *App) Stop(ctx context.Context) error {
	if a.heartbeat != nil {
		a.heartbeat.Stop()
	}

	if a == nil {
		return nil
	}

	a.log.Info().Msg("http: shutting down")

	var errs []error

	if a.srv != nil {
		if err := a.srv.Shutdown(ctx); err != nil {
			a.log.Error().Err(err).Msg("http: shutdown error")
			errs = append(errs, err)
		} else {
			a.log.Info().Msg("http: server stopped")
		}
	}

	// Drain worker queue, bounded by the shutdown deadline.
	if a.Worker != nil {
		if err := a.Worker.Stop(ctx); err != nil {
			a.log.Error().Err(err).Msg("worker: drain did not complete within shutdown deadline")
			errs = append(errs, err)
		} else {
			a.log.Info().Msg("worker: drained")
		}
	}
	// Release any straggler jobs still holding the worker context.
	if a.workerCancel != nil {
		a.workerCancel()
	}

	if a.db != nil {
		if err := pdb.Stop(a.db); err != nil {
			a.log.Error().Err(err).Msg("db: connection pool shutdown error")
			errs = append(errs, err)
		} else {
			a.log.Info().Msg("db: connection pool closed")
		}
	}

	if a.Redis != nil {
		if err := a.Redis.Close(); err != nil {
			a.log.Error().Err(err).Msg("redis: client shutdown error")
			errs = append(errs, err)
		} else {
			a.log.Info().Msg("redis: client closed")
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	a.log.Info().Msg("app: shutdown complete")
	return nil
}
