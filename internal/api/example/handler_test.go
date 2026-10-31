package example

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/note"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const (
	alice uint = 1
	bob   uint = 2
	staff uint = 3
)

type env struct {
	db     *gorm.DB
	router func(authz.Subject) *gin.Engine
}

func newEnv(t *testing.T) *env {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec(`CREATE TABLE notes (
		id integer primary key, created_at datetime, updated_at datetime, deleted_at datetime,
		uuid text, user_id integer, title text, body text)`).Error; err != nil {
		t.Fatal(err)
	}
	return &env{db: db, router: func(s authz.Subject) *gin.Engine {
		r := gin.New()
		secured := r.Group("")
		secured.Use(func(c *gin.Context) {
			middleware.SetActorForTest(c, s)
			c.Next()
		})
		RegisterRoutes(secured, db)
		return r
	}}
}

func (e *env) seed(t *testing.T, owner uint) *note.Note {
	t.Helper()
	n := &note.Note{UUID: uuid.New(), UserID: owner, Title: "t", Body: "b"}
	if err := e.db.Create(n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func call(r http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestRowAccess(t *testing.T) {
	user := authz.Subject{UserID: alice, Role: entities.RoleUser}
	support := authz.Subject{UserID: staff, Role: entities.RoleSupport}
	admin := authz.Subject{UserID: staff, Role: entities.RoleAdmin}

	cases := []struct {
		name   string
		s      authz.Subject
		owner  uint
		method string
		want   int
	}{
		{"owner reads", user, alice, http.MethodGet, http.StatusOK},
		{"owner updates", user, alice, http.MethodPut, http.StatusOK},
		{"owner deletes", user, alice, http.MethodDelete, http.StatusOK},
		{"another user's row reads as missing", user, bob, http.MethodGet, http.StatusNotFound},
		{"another user's row cannot be updated", user, bob, http.MethodPut, http.StatusNotFound},
		{"another user's row cannot be deleted", user, bob, http.MethodDelete, http.StatusNotFound},
		{"support reads any", support, bob, http.MethodGet, http.StatusOK},
		{"support cannot update", support, bob, http.MethodPut, http.StatusForbidden},
		{"support cannot delete", support, bob, http.MethodDelete, http.StatusForbidden},
		{"admin updates any", admin, bob, http.MethodPut, http.StatusOK},
		{"admin deletes any", admin, bob, http.MethodDelete, http.StatusOK},
		{"unknown role is refused", authz.Subject{UserID: alice, Role: "root"}, alice, http.MethodGet, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			n := e.seed(t, tc.owner)
			w := call(e.router(tc.s), tc.method, "/notes/"+n.UUID.String(), `{"title":"changed"}`)
			if w.Code != tc.want {
				t.Fatalf("status %d body %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestListCannotReturnRowsOutOfScope(t *testing.T) {
	e := newEnv(t)
	e.seed(t, alice)
	e.seed(t, alice)
	e.seed(t, bob)

	counts := map[authz.Subject]int{
		{UserID: alice, Role: entities.RoleUser}:    2,
		{UserID: bob, Role: entities.RoleUser}:      1,
		{UserID: staff, Role: entities.RoleUser}:    0,
		{UserID: staff, Role: entities.RoleAdmin}:   3,
		{UserID: staff, Role: entities.RoleSupport}: 3,
	}
	for s, want := range counts {
		w := call(e.router(s), http.MethodGet, "/notes", "")
		if w.Code != http.StatusOK {
			t.Fatalf("%+v: status %d", s, w.Code)
		}
		var body apicommon.PaginatedResponse[NoteResponse]
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Data) != want {
			t.Errorf("%+v: got %d rows, want %d", s, len(body.Data), want)
		}
	}
}

func TestCreateIsGatedAndOwnedByTheActor(t *testing.T) {
	e := newEnv(t)
	if w := call(e.router(authz.Subject{UserID: staff, Role: entities.RoleSupport}), http.MethodPost, "/notes", `{"title":"x"}`); w.Code != http.StatusForbidden {
		t.Fatalf("support create: %d", w.Code)
	}
	w := call(e.router(authz.Subject{UserID: alice, Role: entities.RoleUser}), http.MethodPost, "/notes", `{"title":"x","user_id":99}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("user create: %d %s", w.Code, w.Body.String())
	}
	var n note.Note
	if err := e.db.First(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n.UserID != alice {
		t.Fatalf("owner = %d; the body must not choose the owner", n.UserID)
	}
}
