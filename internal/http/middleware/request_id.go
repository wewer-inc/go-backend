package middleware

import (
	"context"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/reqid"
	utilsconst "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/utils/const"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/utils/generate"
	"github.com/gin-gonic/gin"
)

// RequestIDMiddleware ensures each request carries a unique request ID, echoed
// in the response header and — crucially — stored in the request context so the
// ID is available to every layer below the HTTP boundary (DB, services,
// workers) for log correlation, not just to the access-log line.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Request.Header.Get(utilsconst.ReqIDHeader)
		if id == "" {
			id = generate.UUID()
		}
		c.Writer.Header().Set(utilsconst.ReqIDHeader, id)
		c.Set(utilsconst.ReqIDHeader, id)

		c.Request = c.Request.WithContext(reqid.NewContext(c.Request.Context(), id))

		c.Next()
	}
}

// RequestIDFromContext returns the request ID stored in ctx, or "" if absent.
func RequestIDFromContext(ctx context.Context) string {
	return reqid.FromContext(ctx)
}
