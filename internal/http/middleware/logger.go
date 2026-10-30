package middleware

import (
	"errors"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/dbstats"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// Logger returns a Gin middleware that logs HTTP requests using zerolog and
// attaches a request-scoped child logger (tagged with the request ID) to the
// request context. Downstream code retrieves it via zerolog.Ctx(ctx), so DB
// and service logs correlate to the originating request.
//
// The log level is determined by the response status: Info for <400, Warn for
// 400-499, Error for >=500. Errors attached through c.Error are logged as the
// request's cause, and healthy probe traffic is skipped so it cannot bury real
// requests.
func Logger(log zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := RequestIDFromContext(c.Request.Context())

		reqLog := log.With().Str("request_id", reqID).Logger()
		ctx := reqLog.WithContext(c.Request.Context())
		// Start this request's database counters. Repositories hand this context to GORM,
		// whose callbacks add each query to them.
		ctx, dbStats := dbstats.NewContext(ctx)
		c.Request = c.Request.WithContext(ctx)

		start := time.Now()
		c.Next()
		latency := time.Since(start)
		status := c.Writer.Status()
		path := c.Request.URL.Path

		if (path == "/health" || path == "/ready") && status < 400 {
			return
		}

		evt := reqLog.Info()
		if status >= 500 {
			evt = reqLog.Error()
		} else if status >= 400 {
			evt = reqLog.Warn()
		}

		evt = evt.
			Int("status", status).
			Dur("latency", latency).
			Str("method", c.Request.Method).
			Str("path", path)

		// The route template aggregates without per-id noise.
		if route := c.FullPath(); route != "" {
			evt = evt.Str("route", route)
		}
		if ua := c.Request.UserAgent(); ua != "" {
			evt = evt.Str("user_agent", ua)
		}
		if size := c.Writer.Size(); size >= 0 {
			evt = evt.Int("bytes", size)
		}
		if in := c.Request.ContentLength; in > 0 {
			evt = evt.Int64("bytes_in", in)
		}
		// A client IP is personal data, so it is logged on failures only.
		if status >= 400 {
			evt = evt.Str("client_ip", c.ClientIP())
		}
		// Attribution is ids only, never personal data, and is absent on
		// unauthenticated calls.
		if id, ok := GetActorUserID(c); ok {
			evt = evt.Uint("actor_user_id", id)
		}

		// Callers must not put sensitive values into error strings.
		if len(c.Errors) > 0 {
			evt = evt.Str("error", c.Errors.String())
			var apiErr *apierr.APIError
			if errors.As(c.Errors.Last().Err, &apiErr) {
				evt = evt.Str("error_code", apiErr.Code)
			}
		}

		// Shows whether the time went on the database, an N+1 say, or on application code.
		if q, dbTime := dbStats.Snapshot(); q > 0 {
			evt = evt.Int("db_queries", q).Dur("db_time", dbTime)
		}

		evt.Msg("handled request")
	}
}
