package httpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/versioning"
	"github.com/rs/zerolog"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Sessions live in Postgres, so a deployment with Redis disabled still has auth.
func TestAuthRoutesAreRegisteredWithoutRedis(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewRouter(Deps{Cfg: config.Config{Env: "test"}, Log: zerolog.Nop(), DB: db}, versioning.BuildInfo{})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		method, path string
		want         int
	}{
		// A malformed body proves the route exists without needing any tables.
		{http.MethodPost, "/v1/auth/login", http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/register", http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/refresh", http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/forgot-password", http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/reset-password", http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/mfa/verify", http.StatusBadRequest},
		{http.MethodPost, "/v1/auth/change-password", http.StatusUnauthorized},
		{http.MethodPost, "/v1/auth/mfa/enroll/start", http.StatusUnauthorized},
		{http.MethodPost, "/v1/admin/users/x/mfa/reset", http.StatusUnauthorized},
		{http.MethodPost, "/v1/auth/logout", http.StatusUnauthorized},
		{http.MethodGet, "/v1/auth/sessions", http.StatusUnauthorized},
		{http.MethodDelete, "/v1/auth/sessions", http.StatusUnauthorized},
		{http.MethodDelete, "/v1/auth/sessions/x", http.StatusUnauthorized},
		{http.MethodGet, "/v1/admin/audit", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{"))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
}
