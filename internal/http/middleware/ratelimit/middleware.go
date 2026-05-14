package ratelimit

import (
	"math"
	"net/http"
	"strconv"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	"github.com/gin-gonic/gin"
)

type Middleware struct {
	cfg      config.RateLimitConfig
	resolver *Resolver
	limiter  *Limiter
}

func NewMiddleware(cfg config.RateLimitConfig, limiter *Limiter) *Middleware {
	return &Middleware{
		cfg:      cfg,
		resolver: NewResolver(cfg),
		limiter:  limiter,
	}
}

func (m *Middleware) Global() gin.HandlerFunc {
	return m.BucketHandler(BucketGlobal, m.cfg.Global)
}

func (m *Middleware) Admin() gin.HandlerFunc {
	return m.BucketHandler(BucketAdmin, m.cfg.Admin)
}

func (m *Middleware) Auth() gin.HandlerFunc {
	return m.BucketHandler(BucketAuth, m.cfg.Auth)
}

func (m *Middleware) BucketHandler(bucket Bucket, bcfg config.RateLimitBucketConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !m.cfg.Enabled {
			c.Next()
			return
		}

		// Determine if user actor ID is present
		var actorUserID uint
		if id, ok := middleware.GetActorUserID(c); ok && id > 0 {
			actorUserID = id
		}

		var actorUserID64 int64
		if actorUserID > 0 && actorUserID <= math.MaxInt64 {
			actorUserID64 = int64(actorUserID)
		}

		key, ok := m.resolver.KeyForRequest(c, bucket, actorUserID64)
		if !ok || key == "" {
			// If identity can not be computed, fail closed
			m.respondRateLimited(c, 1)
			return
		}

		allowed, retryAfterSec, err := m.limiter.Allow(c.Request.Context(), key, bcfg)
		if err != nil {
			if retryAfterSec < 1 {
				retryAfterSec = 1
			}
			m.respondRateLimited(c, retryAfterSec)
			return
		}

		if !allowed {
			if retryAfterSec < 1 {
				retryAfterSec = 1
			}
			m.respondRateLimited(c, retryAfterSec)
			return
		}

		c.Next()
	}
}

func (m *Middleware) respondRateLimited(c *gin.Context, retryAfterSeconds int) {
	c.Header("Retry-After", strconv.Itoa(retryAfterSeconds))
	c.JSON(http.StatusTooManyRequests, apicommon.Response[any]{
		Error:   "rate_limited",
		Message: "too many requests",
	})
}
