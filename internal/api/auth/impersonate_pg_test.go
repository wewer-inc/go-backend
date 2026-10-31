//go:build integration

package auth

import (
	"context"
	"net/http"
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
)

func TestImpersonationOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	resp := e.impersonate(t, e.login(t, admin).AccessToken, target)

	if !e.securedOK(t, resp.AccessToken) {
		t.Fatal("token refused")
	}
	if w := e.request(http.MethodPost, "/v1/auth/change-password", resp.AccessToken,
		mustJSON(t, ChangePasswordRequest{CurrentPassword: testPassword, NewPassword: "a-brand-new-password"})); w.Code != http.StatusForbidden {
		t.Fatalf("change password: %d", w.Code)
	}
	if w := e.request(http.MethodPost, "/v1/auth/impersonate/end", resp.AccessToken, ""); w.Code != http.StatusOK {
		t.Fatalf("end: %d %s", w.Code, w.Body.String())
	}
	if e.securedOK(t, resp.AccessToken) {
		t.Fatal("the session should be over")
	}

	for _, event := range []string{audit.EventImpersonationStarted, audit.EventImpersonationEnded} {
		var row audit.Log
		if err := e.db.Where("event = ?", event).First(&row).Error; err != nil {
			t.Fatal(err)
		}
		if row.ImpersonatorUserID == nil || *row.ImpersonatorUserID != admin.ID {
			t.Fatalf("%s: %+v", event, row)
		}
	}
	res, err := auditlog.VerifyStored(context.Background(), e.db, nil)
	if err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
}
