package adminaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func setup(t *testing.T, s authz.Subject) (*gin.Engine, *gorm.DB) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&audit.Log{}); err != nil {
		t.Fatal(err)
	}
	rec := auditlog.NewRecorder(repo.NewGormRepo[audit.Log](db), zerolog.Nop())
	one, two := uint(1), uint(2)
	for _, e := range []auditlog.Entry{
		{Event: audit.EventLoginSuccess, ActorUserID: &one},
		{Event: audit.EventLoginFailure, ActorUserID: &two},
		{Event: audit.EventLoginSuccess, ActorUserID: &two, ImpersonatorUserID: &one},
	} {
		if err := rec.Record(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	r := gin.New()
	g := r.Group("/admin")
	g.Use(func(c *gin.Context) { middleware.SetActorForTest(c, s); c.Next() })
	RegisterRoutes(g, db)
	return r, db
}

func get(r http.Handler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

var admin = authz.Subject{UserID: 1, Role: entities.RoleAdmin}

func TestOnlyAuditReadersGetThrough(t *testing.T) {
	cases := map[entities.Role]int{
		entities.RoleUser:    http.StatusForbidden,
		entities.RoleSupport: http.StatusForbidden,
		entities.RoleAdmin:   http.StatusOK,
	}
	for role, want := range cases {
		r, _ := setup(t, authz.Subject{UserID: 1, Role: role})
		for _, path := range []string{"/admin/audit", "/admin/audit/verify"} {
			if w := get(r, path); w.Code != want {
				t.Errorf("%s on %s: %d", role, path, w.Code)
			}
		}
	}
}

func TestListFiltersAndServesNewestFirst(t *testing.T) {
	r, _ := setup(t, admin)
	cases := []struct {
		query string
		want  int
	}{
		{"", 3},
		{"?event=login.success", 2},
		{"?actor_user_id=2", 2},
		{"?impersonator_user_id=1", 1},
		{"?page_size=1", 1},
	}
	for _, tc := range cases {
		w := get(r, "/admin/audit"+tc.query)
		if w.Code != http.StatusOK {
			t.Fatalf("%q: %d", tc.query, w.Code)
		}
		var body apicommon.PaginatedResponse[LogResponse]
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data) != tc.want {
			t.Errorf("%q: %d rows, want %d", tc.query, len(body.Data), tc.want)
		}
		if tc.query == "" && (body.Data[0].ID < body.Data[1].ID || body.Data[0].Hash == "") {
			t.Errorf("unexpected order or missing hash: %+v", body.Data)
		}
	}
	if w := get(r, "/admin/audit?page_size=abc"); w.Code != http.StatusBadRequest {
		t.Errorf("bad query: %d", w.Code)
	}
}

func readVerify(t *testing.T, r http.Handler, query string) auditlog.VerifyResult {
	t.Helper()
	w := get(r, "/admin/audit/verify"+query)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body apicommon.Response[auditlog.VerifyResult]
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return *body.Data
}

func TestVerifyReportsTampering(t *testing.T) {
	r, db := setup(t, admin)
	if res := readVerify(t, r, ""); !res.OK || res.Checked != 3 || res.CheckpointVerified {
		t.Fatalf("%+v", res)
	}
	if err := db.Exec(`DELETE FROM audit_logs WHERE id = 2`).Error; err != nil {
		t.Fatal(err)
	}
	if res := readVerify(t, r, ""); res.OK || res.FirstBadID != 3 {
		t.Fatalf("%+v", res)
	}
}

func TestVerifyWithACheckpointCatchesTailTruncation(t *testing.T) {
	r, db := setup(t, admin)
	head := readVerify(t, r, "")
	query := fmt.Sprintf("?checkpoint_id=%d&checkpoint_hash=%s", head.HeadID, head.Head)
	if res := readVerify(t, r, query); !res.OK || !res.CheckpointVerified {
		t.Fatalf("%+v", res)
	}
	if err := db.Exec(`DELETE FROM audit_logs WHERE id = 3`).Error; err != nil {
		t.Fatal(err)
	}
	if res := readVerify(t, r, ""); !res.OK {
		t.Fatalf("without a checkpoint truncation is invisible: %+v", res)
	}
	if res := readVerify(t, r, query); res.OK || res.Reason != auditlog.ReasonCheckpointMissing {
		t.Fatalf("%+v", res)
	}
	wrong := fmt.Sprintf("?checkpoint_id=1&checkpoint_hash=%s", strings.Repeat("a", 64))
	if res := readVerify(t, r, wrong); res.OK || res.Reason != auditlog.ReasonCheckpointMismatch {
		t.Fatalf("%+v", res)
	}
}

func TestVerifyRefusesAHalfCheckpoint(t *testing.T) {
	r, _ := setup(t, admin)
	for _, q := range []string{
		"?checkpoint_id=1",
		"?checkpoint_hash=" + strings.Repeat("a", 64),
		"?checkpoint_id=1&checkpoint_hash=short",
		"?checkpoint_id=abc&checkpoint_hash=" + strings.Repeat("a", 64),
	} {
		if w := get(r, "/admin/audit/verify"+q); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
}
