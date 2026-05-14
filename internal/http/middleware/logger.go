package middleware

import (
	"time"

	utilsconst "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/utils/const"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// loggerMiddleware returns a Gin middleware that logs HTTP requests using zerolog.
// It records the request's status code, latency, method, path, and request ID.
// The log level is determined by the response status: Info for <400, Warn for 400-499, Error for >=500.
// The middleware logs after the request is processed.
func Logger(log zerolog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)
		status := c.Writer.Status()
		method := c.Request.Method
		path := c.Request.URL.Path
		reqID, _ := c.Get(utilsconst.ReqIDHeader)

		evt := log.Info()
		if status >= 500 {
			evt = log.Error()
		} else if status >= 400 {
			evt = log.Warn()
		}

		evt.
			Int("status", status).
			Dur("latency", latency).
			Str("method", method).
			Str("path", path).
			Str("request_id", reqID.(string)).
			Msg("handled request")
	}
}
