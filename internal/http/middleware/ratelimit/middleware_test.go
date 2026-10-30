package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	goredis "github.com/redis/go-redis/v9"
)

func newMiddleware(t *testing.T, bucket config.RateLimitBucketConfig) *Middleware {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cfg := config.RateLimitConfig{Enabled: true, Global: bucket, Auth: bucket, Admin: bucket}
	return NewMiddleware(cfg, &Limiter{rdb: client})
}

func tightBucket() config.RateLimitBucketConfig {
	return config.RateLimitBucketConfig{RPM: 1, Burst: 0}
}

func TestDeniedRequestNeverReachesTheHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newMiddleware(t, tightBucket())
	ran := 0
	r := gin.New()
	r.Use(m.Auth())
	r.GET("/x", func(c *gin.Context) {
		ran++
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	do := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.RemoteAddr = "203.0.113.9:1234"
		r.ServeHTTP(w, req)
		return w
	}

	if w := do(); w.Code != http.StatusOK {
		t.Fatalf("first request: %d", w.Code)
	}
	w := do()
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: %d", w.Code)
	}
	if ran != 1 {
		t.Fatalf("handler ran %d times; a denied request must not reach it", ran)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("429 body is not one JSON document: %v (%s)", err, w.Body.String())
	}
}

func TestKeyedBucketIsPerKeyAndFailsClosedWithoutOne(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newMiddleware(t, tightBucket())
	r := gin.New()
	r.Use(m.Keyed(BucketGlobal, tightBucket(), func(c *gin.Context) string { return c.GetHeader("X-Key") }))
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	do := func(key string) int {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if key != "" {
			req.Header.Set("X-Key", key)
		}
		r.ServeHTTP(w, req)
		return w.Code
	}

	if got := do("a"); got != http.StatusOK {
		t.Fatalf("first a: %d", got)
	}
	if got := do("a"); got != http.StatusTooManyRequests {
		t.Fatalf("second a: %d", got)
	}
	if got := do("b"); got != http.StatusOK {
		t.Fatalf("b must have its own budget: %d", got)
	}
	if got := do(""); got != http.StatusTooManyRequests {
		t.Fatalf("no key must fail closed: %d", got)
	}
}
