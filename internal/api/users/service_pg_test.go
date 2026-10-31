//go:build integration

package users

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	pdb "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/db"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/pgtest"
	"github.com/rs/zerolog"
)

func newPGEnv(t *testing.T) *env {
	t.Helper()
	db := pgtest.Open(t)
	if err := pdb.UpMigrations(db, zerolog.Nop()); err != nil {
		t.Fatal(err)
	}
	return wire(t, db, auditlog.NewGormRecorder(db, zerolog.Nop()))
}

func (e *env) countAdmins(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := e.db.Model(&user.User{}).Where("platform_role = ?", entities.RoleAdmin).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestChangeRoleOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	admin, target := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleUser)
	targetToken := e.signIn(t, target, nil)
	if w := e.patch(t, e.signIn(t, admin, nil), target.UUID.String(), string(entities.RoleSupport)); w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if e.stillSignedIn(t, targetToken) {
		t.Fatal("the target's sessions must be revoked")
	}
	if got := e.roleOf(t, target); got != entities.RoleSupport {
		t.Fatalf("role = %q", got)
	}
	res, err := auditlog.VerifyStored(context.Background(), e.db, nil)
	if err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
}

// Two admins demoting each other at once would each count two admins and leave none.
func TestMutualDemotionLeavesAnAdminOnPostgres(t *testing.T) {
	for round := 0; round < 5; round++ {
		e := newPGEnv(t)
		a, b := e.addUser(t, entities.RoleAdmin), e.addUser(t, entities.RoleAdmin)
		aSubject := authz.Subject{UserID: a.ID, Role: entities.RoleAdmin}
		bSubject := authz.Subject{UserID: b.ID, Role: entities.RoleAdmin}

		var wg sync.WaitGroup
		var succeeded atomic.Int32
		start := make(chan struct{})
		demote := func(actor authz.Subject, target *user.User) {
			defer wg.Done()
			<-start
			if _, err := e.svc.ChangeRole(context.Background(), actor, target.UUID.String(), string(entities.RoleUser), ""); err == nil {
				succeeded.Add(1)
			}
		}
		wg.Add(2)
		go demote(aSubject, b)
		go demote(bSubject, a)
		close(start)
		wg.Wait()

		if succeeded.Load() != 1 {
			t.Fatalf("round %d: %d demotions succeeded", round, succeeded.Load())
		}
		if n := e.countAdmins(t); n != 1 {
			t.Fatalf("round %d: %d admins remain", round, n)
		}
	}
}

func TestParallelSelfDemotionsLeaveAnAdminOnPostgres(t *testing.T) {
	e := newPGEnv(t)
	const n = 6
	admins := make([]*user.User, n)
	for i := range admins {
		admins[i] = e.addUser(t, entities.RoleAdmin)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, a := range admins {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			actor := authz.Subject{UserID: a.ID, Role: entities.RoleAdmin}
			_, _ = e.svc.ChangeRole(context.Background(), actor, a.UUID.String(), string(entities.RoleUser), "")
		}()
	}
	close(start)
	wg.Wait()
	if got := e.countAdmins(t); got != 1 {
		t.Fatalf("%d admins remain", got)
	}
	if rows := e.events(t, audit.EventUserRoleChanged); len(rows) != n-1 {
		t.Fatalf("%d change rows", len(rows))
	}
	res, err := auditlog.VerifyStored(context.Background(), e.db, nil)
	if err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
}
