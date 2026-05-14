package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
)

var cfglog = zerolog.New(os.Stdout).With().Timestamp().Str("component", "config").Logger()

type S3Config struct {
	Bucket             string
	Region             string
	Endpoint           string
	UsePathStyle       bool
	PresignUploadTTL   time.Duration
	PresignDownloadTTL time.Duration
	MaxObjMB           int
	AllowedMIMEs       []string
	BasePrefix         string // optional, can keep empty
}

type JWTConfig struct {
	SecretKey          string
	TokenIssuer        string
	TokenExpiration    time.Duration // access token expiry
	RefreshTokenExpiry time.Duration
}

type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type SMTPConfig struct {
	Host     string
	Port     int
	From     string
	Password string
	UseTLS   bool
}

type RedisConfig struct {
	Addr         string
	Username     string
	Password     string
	DB           int
	TLSEnable    bool
	PoolSize     int
	MinIdleConns int
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type RateLimitBucketConfig struct {
	RPM   int
	Burst int
}

type RateLimitConfig struct {
	Enabled    bool
	TrustProxy bool
	Global     RateLimitBucketConfig
	Auth       RateLimitBucketConfig
	Admin      RateLimitBucketConfig
}

type Config struct {
	Env      string // dev | staging | prod
	Port     string // e.g. "8080"
	LogLevel string // e.g. "debug", "info", "warn", "error"

	// DB Context timeout for per-operation deadlines
	DBContextTimeout time.Duration // default to 2 seconds for now

	// Ready Checks Timeout Period
	ReadyCheckTimeout time.Duration // default to 3 seconds for now

	// --- Database Bootstrap Settings ---
	DB_DSN              string
	DB_MIGRATE_ON_START bool
	DB_MAX_OPEN         int
	DB_MAX_IDLE         int
	DB_CONN_LIFETIME    time.Duration
	DB_CONN_IDLE_TIME   time.Duration
	DB_SLOW_THRESHOLD   time.Duration

	// --- S3 Settings ---
	S3 S3Config

	// --- JWT Settings ---
	JWT JWTConfig

	// --- Redis Settings ---
	Redis RedisConfig

	// --- Rate Limiting Settings ---
	RateLimit RateLimitConfig

	// --- CORS Settings ---
	CORSAllowedOrigins []string

	// --- Google OAuth ---
	Google GoogleOAuthConfig

	// --- Email / SMTP ---
	SMTP SMTPConfig
}

// Load reads environment variables.
// In non-prod, it will also attempt to load .env file if present.
func Load() Config {
	// Best-effort: load .env file in dev-like environments (ignore errors).

	if _, err := os.Stat(".env"); err == nil {
		_ = godotenv.Load()
	}

	cfg := Config{
		Env:                getEnv("APP_ENV", "dev"),
		Port:               getEnv("APP_PORT", "8080"),
		LogLevel:           getEnv("APP_LOG_LEVEL", "debug"),
		S3:                 loadS3(),
		JWT:                loadJWT(),
		Redis:              loadRedis(),
		RateLimit:          loadRateLimitConfig(),
		CORSAllowedOrigins: parseCSV("CORS_ALLOWED_ORIGINS", "*"),
		Google:             loadGoogle(),
		SMTP:               loadSMTP(),
	}

	// Ready check timeout period
	cfg.ReadyCheckTimeout = parseDuration("READY_CHECK_TIMEOUT", 3*time.Second)

	// DB context timeout (operation-level timeout)
	cfg.DBContextTimeout = parseDuration("DB_CONTEXT_TIMEOUT", 2*time.Second)

	// DB Core Settings
	cfg.DB_DSN = getEnv("DB_DSN", "")
	cfg.DB_MIGRATE_ON_START = parseBool("DB_MIGRATE_ON_START", false)
	cfg.DB_MAX_OPEN = parseInt("DB_MAX_OPEN", 25)
	cfg.DB_MAX_IDLE = parseInt("DB_MAX_IDLE", 5)
	cfg.DB_CONN_LIFETIME = parseDuration("DB_CONN_LIFETIME", 30*time.Minute)
	cfg.DB_CONN_IDLE_TIME = parseDuration("DB_CONN_IDLE_TIME", 9*time.Minute)
	cfg.DB_SLOW_THRESHOLD = parseDuration("DB_SLOW_THRESHOLD", 200*time.Millisecond)

	return cfg
}

// ----------------------Helpers----------------------

func loadJWT() JWTConfig {
	return JWTConfig{
		SecretKey:          getEnv("JWT_SECRET", "change_me_please"),
		TokenIssuer:        getEnv("JWT_ISSUER", "YOUR_APP_NAME"),
		TokenExpiration:    parseDuration("JWT_ACCESS_EXPIRY", 15*time.Minute),
		RefreshTokenExpiry: parseDuration("JWT_REFRESH_EXPIRY", 168*time.Hour), // 7 days
	}
}

func loadGoogle() GoogleOAuthConfig {
	return GoogleOAuthConfig{
		ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		RedirectURL:  getEnv("GOOGLE_REDIRECT_URL", ""),
	}
}

func loadS3() S3Config {
	return S3Config{
		Bucket:             getEnv("S3_BUCKET", ""),
		Region:             getEnv("S3_REGION", ""),
		Endpoint:           getEnv("S3_ENDPOINT", ""),
		UsePathStyle:       parseBool("S3_USE_PATH_STYLE", false),
		PresignUploadTTL:   parseDuration("S3_PRESIGN_UPLOAD_TTL", 900*time.Second),
		PresignDownloadTTL: parseDuration("S3_PRESIGN_DOWNLOAD_TTL", 900*time.Second),
		MaxObjMB:           parseInt("S3_MAX_OBJ_MB", 25),
		AllowedMIMEs:       parseCSV("S3_ALLOWED_MIMES", "image/jpeg,image/png,image/webp"),
		BasePrefix:         getEnv("S3_BASE_PREFIX", ""),
	}
}

func loadRedis() RedisConfig {
	return RedisConfig{
		Addr:         getEnv("REDIS_ADDR", "localhost:6379"),
		Username:     getEnv("REDIS_USERNAME", ""),
		Password:     getEnv("REDIS_PASSWORD", ""),
		DB:           parseInt("REDIS_DB", 0),
		TLSEnable:    parseBool("REDIS_TLS_ENABLE", false),
		PoolSize:     parseInt("REDIS_POOL_SIZE", 10),
		MinIdleConns: parseInt("REDIS_MIN_IDLE", 2),
		DialTimeout:  parseDuration("REDIS_DIAL_TIMEOUT_MS", 500*time.Millisecond),
		ReadTimeout:  parseDuration("REDIS_READ_TIMEOUT_MS", 500*time.Millisecond),
		WriteTimeout: parseDuration("REDIS_WRITE_TIMEOUT_MS", 500*time.Millisecond),
	}
}

func loadSMTP() SMTPConfig {
	return SMTPConfig{
		Host:     getEnv("SMTP_HOST", ""),
		Port:     parseInt("SMTP_PORT", 587),
		From:     getEnv("SMTP_FROM", ""),
		Password: getEnv("SMTP_PASSWORD", ""),
		UseTLS:   parseBool("SMTP_USE_TLS", false),
	}
}

func loadRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:    parseBool("RATE_LIMIT_ENABLED", true),
		TrustProxy: parseBool("RATE_LIMIT_TRUST_PROXY", false),

		Global: RateLimitBucketConfig{
			RPM:   parseInt("RATE_LIMIT_GLOBAL_RPM", 60),
			Burst: parseInt("RATE_LIMIT_GLOBAL_BURST", 30),
		},

		Admin: RateLimitBucketConfig{
			RPM:   parseInt("RATE_LIMIT_ADMIN_RPM", 60),
			Burst: parseInt("RATE_LIMIT_ADMIN_BURST", 30),
		},

		Auth: RateLimitBucketConfig{
			RPM:   parseInt("RATE_LIMIT_AUTH_RPM", 60),
			Burst: parseInt("RATE_LIMIT_AUTH_BURST", 30),
		},
	}
}

func getEnv(k, def string) string {
	v := os.Getenv(k)

	if v == "" {
		cfglog.Warn().
			Str("key", k).
			Str("value", v).
			Msg(fmt.Sprintf("env var %s not set, using default %s", k, def))
		return def
	}
	return v
}

func parseInt(k string, def int) int {
	v := os.Getenv(k)

	if v == "" {
		return def
	}

	i, err := strconv.Atoi(v)
	if err != nil {
		cfglog.Warn().
			Str("key", k).
			Str("value", v).
			Msg(fmt.Sprintf("invalid integer for env var %s, using default %d", k, def))
		return def
	}

	return i
}

func parseBool(k string, def bool) bool {
	v := os.Getenv(k)

	if v == "" {
		return def
	}

	switch v {
	case "1", "true", "TRUE", "True", "yes", "YES", "Yes":
		return true
	case "0", "false", "FALSE", "False", "no", "NO", "No":
		return false
	default:
		cfglog.Warn().
			Str("key", k).
			Str("value", v).
			Msg(fmt.Sprintf("invalid boolean for env var %s, using default %t", k, def))
		return def
	}
}

func parseDuration(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)

	if v == "" {
		return def
	}

	d, err := time.ParseDuration(v)
	if err != nil {
		cfglog.Warn().
			Str("key", k).
			Str("value", v).
			Msg(fmt.Sprintf("invalid duration for env var %s, using default %s", k, def))
		return def
	}

	return d
}

func parseCSV(k, def string) []string {
	v := strings.TrimSpace(os.Getenv(k))

	if v == "" {
		v = def
	}

	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}

	return out
}
