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
		resolver: NewResolver(),
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

// Keyed limits by the string keyFn returns and ignores the actor and IP, which suits machine
// callers such as those holding a partner API key. A request with no key is rejected.
func (m *Middleware) Keyed(bucket Bucket, bcfg config.RateLimitBucketConfig, keyFn func(*gin.Context) string) gin.HandlerFunc {
	prefix := "rl:" + string(bucket) + ":key:"
	return func(c *gin.Context) {
		if m.cfg.Enabled && !m.admitKey(c, prefix, keyFn(c), bcfg) {
			return
		}
		c.Next()
	}
}

func (m *Middleware) admitKey(c *gin.Context, prefix, id string, bcfg config.RateLimitBucketConfig) bool {
	if id == "" {
		m.respondRateLimited(c, 1)
		return false
	}
	allowed, retryAfterSec, err := m.limiter.Allow(c.Request.Context(), prefix+id, bcfg)
	if err == nil && allowed {
		return true
	}
	m.respondRateLimited(c, max(retryAfterSec, 1))
	return false
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

// respondRateLimited sends the 429 and stops the chain. Sending alone would not limit
// anything: Context.Next runs middleware in a loop that a plain return does not break, so
// the rejected request would carry on to its handler, do all its database work and append
// a second JSON body to the response.
func (m *Middleware) respondRateLimited(c *gin.Context, retryAfterSeconds int) {
	c.Header("Retry-After", strconv.Itoa(retryAfterSeconds))
	c.AbortWithStatusJSON(http.StatusTooManyRequests, apicommon.Response[any]{
		Error:   "rate_limited",
		Message: "too many requests",
	})
}
