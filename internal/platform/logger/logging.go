package logger

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"

	pc "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
)

// NewLogger creates and configures a zerolog.Logger instance based on the provided configuration.
// It sets the log level, timestamp format, and environment field. In production ("prod") environment,
// it outputs logs in JSON format to stdout. In other environments, it outputs logs in a human-readable
// console format. The logger includes a timestamp and the environment name in each log entry.
func NewLogger(cfg pc.Config) zerolog.Logger {
	level := parseLevel(cfg.LogLevel)
	zerolog.TimeFieldFormat = time.RFC3339
	zerolog.TimestampFieldName = "ts"

	// Dev: pretty console; Prod: JSON
	if cfg.Env == "prod" {
		l := zerolog.New(os.Stdout).Level(level).With().Timestamp().Str("env", cfg.Env).Logger()
		return l
	}

	console := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:11:11"}
	l := zerolog.New(console).Level(level).With().Timestamp().Str("env", cfg.Env).Logger()
	return l
}

func parseLevel(v string) zerolog.Level {
	switch strings.ToLower(v) {
	case "trace":
		return zerolog.TraceLevel
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn", "warning":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	default:
		return zerolog.InfoLevel
	}
}
