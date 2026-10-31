package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/gin-gonic/gin"
)

func gated(subject *authz.Subject, gate gin.HandlerFunc) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if subject != nil {
			c.Set(ctxActorSubject, *subject)
		}
	})
	r.GET("/x", gate, func(c *gin.Context) { c.Status(http.StatusOK) })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/x", nil))
	return w
}

func TestPermissionGateStatusBySubject(t *testing.T) {
	gate := RequirePermission(authz.ResAdminUsers, authz.ActionRead)
	cases := []struct {
		name string
		s    *authz.Subject
		want int
	}{
		{"no subject fails closed", nil, http.StatusUnauthorized},
		{"role without the grant", &authz.Subject{UserID: 1, Role: entities.RoleUser}, http.StatusForbidden},
		{"role with the grant", &authz.Subject{UserID: 1, Role: entities.RoleSupport}, http.StatusOK},
		{"unknown role", &authz.Subject{UserID: 1, Role: "root"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		if w := gated(tc.s, gate); w.Code != tc.want {
			t.Errorf("%s: status %d", tc.name, w.Code)
		}
	}
}

func TestRequireCapabilityAppliesTheImpersonationBar(t *testing.T) {
	gate := RequireCapability(authz.CapUsersRoleUpdate)
	imp := uint(9)
	cases := []struct {
		name string
		s    *authz.Subject
		want int
	}{
		{"no subject fails closed", nil, http.StatusUnauthorized},
		{"role without it", &authz.Subject{UserID: 1, Role: entities.RoleSupport}, http.StatusForbidden},
		{"role with it", &authz.Subject{UserID: 1, Role: entities.RoleAdmin}, http.StatusOK},
		{"role with it inside login-as", &authz.Subject{UserID: 1, Role: entities.RoleAdmin, Impersonator: &imp}, http.StatusForbidden},
	}
	for _, tc := range cases {
		if w := gated(tc.s, gate); w.Code != tc.want {
			t.Errorf("%s: status %d", tc.name, w.Code)
		}
	}
}
