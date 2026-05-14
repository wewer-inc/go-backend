package httpserver

import (
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
)

func NewRouter(deps Deps, build versioning.BuildInfo) http.Handler {
	if deps.Cfg.Env == "prod" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(
		middleware.RequestIDMiddleware(),
		middleware.Logger(deps.Log),
		metrics.Middleware(),
	)

	// CORS — driven by CORS_ALLOWED_ORIGINS env var
	allowedOrigins := deps.Cfg.CORSAllowedOrigins
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"*"}
	}
	r.Use(cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Authorization", "Content-Type", "X-Request-ID"},
		AllowCredentials: !containsWildcard(allowedOrigins),
	}))

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

	jwtVerifier := platformauth.NewJWTVerifier(deps.Cfg.JWT.SecretKey, deps.Cfg.JWT.TokenIssuer)
	jwtIssuer := platformauth.NewJWTIssuer(
		deps.Cfg.JWT.SecretKey,
		deps.Cfg.JWT.TokenIssuer,
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
	if rl != nil {
		v1.Use(rl.Global())
	}

	// Auth routes (unauthenticated)
	if deps.Redis != nil {
		apiauth.RegisterRoutes(v1, deps.Cfg, userRepo, jwtIssuer, jwtVerifier, deps.Redis.Raw())
	}

	// Authenticated routes
	secured := v1.Group("")
	secured.Use(middleware.UserAuth(jwtVerifier, userRepo))

	example.RegisterRoutes(secured, deps.DB)

	// Admin routes
	admin := v1.Group("/admin")
	if rl != nil {
		admin.Use(rl.Admin())
	}
	admin.Use(middleware.AdminAuth(jwtVerifier, userRepo))

	return r
}

func containsWildcard(origins []string) bool {
	for _, o := range origins {
		if strings.TrimSpace(o) == "*" {
			return true
		}
	}
	return false
}
