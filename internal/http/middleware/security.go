package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SecurityHeaders sets baseline security response headers. HSTS is only emitted
// when the request is served over TLS (directly or via a trusted proxy that set
// X-Forwarded-Proto=https), so it doesn't break plain-HTTP local development.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}

// BodyLimit caps the size of request bodies to maxBytes, returning 413 when
// exceeded. This prevents a trivial memory-exhaustion DoS from oversized
// payloads reaching json decoding. A non-positive maxBytes disables the limit.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if maxBytes > 0 && c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}
