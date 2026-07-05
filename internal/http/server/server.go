package httpserver

import (
	"fmt"
	"net/http"
	"strings"

	apiauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/example"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware/ratelimit"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	pdb "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/db"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/metrics"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/versioning"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
)

func NewRouter(deps Deps, build versioning.BuildInfo) (http.Handler, error) {
	if deps.Cfg.Env == "prod" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	r := gin.New()

	// Trusted proxies: only honour X-Forwarded-For from these hops when deriving
	// ClientIP. Empty list => XFF is ignored (ClientIP == direct peer), which is
	// the safe default for the rate limiter. A malformed CIDR here must fail the
	// build rather than silently leave gin on an unsafe default.
	if err := r.SetTrustedProxies(deps.Cfg.TrustedProxies); err != nil {
		return nil, fmt.Errorf("http: invalid TRUSTED_PROXIES: %w", err)
	}

	r.Use(gin.Recovery())
	r.Use(
		middleware.RequestIDMiddleware(),
		middleware.Logger(deps.Log),
		middleware.SecurityHeaders(),
		middleware.BodyLimit(deps.Cfg.MaxRequestBodyBytes),
		metrics.Middleware(),
	)

	// CORS — driven by CORS_ALLOWED_ORIGINS. Fail closed: when no origins are
	// configured we skip CORS entirely (same-origin only) rather than allowing all.
	allowedOrigins := deps.Cfg.CORSAllowedOrigins
	if len(allowedOrigins) > 0 {
		r.Use(cors.New(cors.Config{
			AllowOrigins:     allowedOrigins,
			AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowHeaders:     []string{"Authorization", "Content-Type", "X-Request-ID"},
			AllowCredentials: !containsWildcard(allowedOrigins),
		}))
	} else {
		deps.Log.Warn().Msg("cors: no allowed origins configured; cross-origin browser requests will be blocked")
	}

	// Prometheus scrape endpoint (no auth)
	r.GET("/metrics", metrics.Handler())

	// Liveness probe
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"version": build.Version,
			"env":     deps.Cfg.Env,
		})
	})

	// Readiness probe: checks DB + Redis
	r.GET("/ready", func(c *gin.Context) {
		if err := pdb.ReadyCheck(c.Request.Context(), deps.DB, deps.Cfg.DBContextTimeout); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "error": "db_not_ready"})
			return
		}
		if deps.Redis != nil {
			if err := deps.Redis.HealthCheck(c.Request.Context()); err != nil {
				c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "error": "redis_not_ready"})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// Version info
	r.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version":   build.Version,
			"commit":    build.Commit,
			"buildTime": build.Date,
		})
	})

	jwtVerifier := platformauth.NewJWTVerifier(
		deps.Cfg.JWT.SecretKey,
		deps.Cfg.JWT.TokenIssuer,
		deps.Cfg.JWT.TokenAudience,
	)
	jwtIssuer := platformauth.NewJWTIssuer(
		deps.Cfg.JWT.SecretKey,
		deps.Cfg.JWT.TokenIssuer,
		deps.Cfg.JWT.TokenAudience,
		deps.Cfg.JWT.TokenExpiration,
		deps.Cfg.JWT.RefreshTokenExpiry,
	)
	userRepo := repo.NewGormRepo[user.User](deps.DB)

	v1 := r.Group("/v1")

	var rl *ratelimit.Middleware
	if deps.Redis != nil {
		rlLimiter := ratelimit.NewLimiter(deps.Redis)
		rl = ratelimit.NewMiddleware(deps.Cfg.RateLimit, rlLimiter)
	}

	var rawRedis *goredis.Client
	if deps.Redis != nil {
		rawRedis = deps.Redis.Raw()
	}

	// Authenticated group. Rate limiting is applied AFTER UserAuth so the limit
	// is keyed by user id (not the shared NAT/proxy IP).
	failOpen := deps.Cfg.AuthRevocationFailOpen
	secured := v1.Group("")
	secured.Use(middleware.UserAuth(jwtVerifier, userRepo, rawRedis, failOpen))
	if rl != nil {
		secured.Use(rl.Global())
	}

	// Auth routes: public endpoints get the strict Auth bucket (IP-keyed);
	// logout is registered on the authenticated group.
	if deps.Redis != nil {
		var authLimit gin.HandlerFunc
		if rl != nil {
			authLimit = rl.Auth()
		}
		apiauth.RegisterRoutes(v1, secured, deps.Cfg, userRepo, jwtIssuer, jwtVerifier, rawRedis, authLimit)
	}

	example.RegisterRoutes(secured, deps.DB)

	// Admin routes: AdminAuth first (sets identity), then the admin bucket so it
	// is user-keyed.
	admin := v1.Group("/admin")
	admin.Use(middleware.AdminAuth(jwtVerifier, userRepo, rawRedis, failOpen))
	if rl != nil {
		admin.Use(rl.Admin())
	}

	return r, nil
}

func containsWildcard(origins []string) bool {
	for _, o := range origins {
		if strings.TrimSpace(o) == "*" {
			return true
		}
	}
	return false
}
