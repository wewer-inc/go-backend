package middleware

import (
	utilsconst "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/utils/const"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/utils/generate"
	"github.com/gin-gonic/gin"
)

// RequestIDMiddleware is a Gin middleware that ensures each HTTP request has a unique request ID.
// It checks for an existing request ID in the incoming request header specified by reqIDHeader.
// If no request ID is found, it generates a new UUID and sets it as the request ID in the response header.
// This middleware allows for consistent request tracking and correlation across services.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Request.Header.Get(utilsconst.ReqIDHeader)
		if id == "" {
			id = generate.UUID()
		}
		c.Writer.Header().Set(utilsconst.ReqIDHeader, id)
		c.Set(utilsconst.ReqIDHeader, id)
		c.Next()
	}
}
