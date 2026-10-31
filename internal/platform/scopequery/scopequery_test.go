package scopequery

import (
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
)

func TestForOwned(t *testing.T) {
	cases := []struct {
		name string
		s    authz.Subject
		res  authz.Resource
		expr string
	}{
		{"own", authz.Subject{UserID: 7, Role: entities.RoleUser}, authz.ResNote, "user_id = ?"},
		{"global", authz.Subject{UserID: 1, Role: entities.RoleAdmin}, authz.ResNote, "1 = 1"},
		{"no grant", authz.Subject{UserID: 7, Role: entities.RoleUser}, authz.ResAdminUsers, "1 = 0"},
		{"unknown role", authz.Subject{UserID: 7, Role: "root"}, authz.ResNote, "1 = 0"},
		{"zero subject", authz.Subject{Role: entities.RoleUser}, authz.ResNote, "1 = 0"},
		{"empty subject", authz.Subject{}, authz.ResNote, "1 = 0"},
	}
	for _, tc := range cases {
		if got := ForOwned(tc.s, tc.res, "user_id"); got.Expr != tc.expr {
			t.Errorf("%s: got %q", tc.name, got.Expr)
		}
	}
	got := ForOwned(cases[0].s, authz.ResNote, "user_id")
	if len(got.Args) != 1 || got.Args[0] != uint(7) {
		t.Errorf("args = %v", got.Args)
	}
}
