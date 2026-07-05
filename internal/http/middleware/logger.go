package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// Logger returns a Gin middleware that logs HTTP requests using zerolog and
// attaches a request-scoped child logger (tagged with the request ID) to the
// request context. Downstream code retrieves it via zerolog.Ctx(ctx), so DB
// and service logs correlate to the originating request.
//
// The log level is determined by the response status: Info for <400, Warn for
// 400-499, Error for >=500.
func Logger(log zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqID := RequestIDFromContext(c.Request.Context())

		reqLog := log.With().Str("request_id", reqID).Logger()
		c.Request = c.Request.WithContext(reqLog.WithContext(c.Request.Context()))

		start := time.Now()
		c.Next()
		latency := time.Since(start)
		status := c.Writer.Status()

		evt := reqLog.Info()
		if status >= 500 {
			evt = reqLog.Error()
		} else if status >= 400 {
			evt = reqLog.Warn()
		}

		evt.
			Int("status", status).
			Dur("latency", latency).
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Msg("handled request")
	}
}
