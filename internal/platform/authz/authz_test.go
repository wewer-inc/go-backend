package authz

import (
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
)

// TestMatrixFixture is the policy, restated. Changing a grant means changing it here
// too, on purpose, in the same reviewed diff.
func TestMatrixFixture(t *testing.T) {
	const c, r, u, d = "c", "r", "u", "d"
	want := map[entities.Role]map[Resource][]string{
		entities.RoleUser:    {ResNote: {c, r, u, d}, ResAdminUsers: {}, ResAdminAudit: {}},
		entities.RoleSupport: {ResNote: {r}, ResAdminUsers: {r}, ResAdminAudit: {}},
		entities.RoleAdmin:   {ResNote: {c, r, u, d}, ResAdminUsers: {c, r, u, d}, ResAdminAudit: {r}},
	}
	letter := map[Action]string{ActionCreate: c, ActionRead: r, ActionUpdate: u, ActionDelete: d}
	for _, role := range entities.AllRoles() {
		for _, res := range AllResources() {
			held := map[string]bool{}
			for _, l := range want[role][res] {
				held[l] = true
			}
			for _, a := range AllActions() {
				if got := Can(role, res, a); got != held[letter[a]] {
					t.Errorf("%s %s %s: got %v, want %v", role, res, a, got, held[letter[a]])
				}
			}
		}
	}
}

func TestPolicyIsComplete(t *testing.T) {
	for _, role := range entities.AllRoles() {
		for _, res := range AllResources() {
			if _, ok := matrix[role][res]; !ok {
				t.Errorf("matrix has no entry for %s on %s", role, res)
			}
			if _, ok := scopes[role][res]; !ok {
				t.Errorf("scopes has no entry for %s on %s", role, res)
			}
		}
	}
	for _, c := range AllCapabilities() {
		if _, ok := capabilities[c]; !ok {
			t.Errorf("capability %s has no holders table", c)
		}
	}
	for role := range matrix {
		if !role.Valid() {
			t.Errorf("matrix authors unknown role %q", role)
		}
	}
}

// A role that can act on a resource must reach some rows of it, or the grant is dead.
func TestEveryGrantHasReach(t *testing.T) {
	for _, role := range entities.AllRoles() {
		for _, res := range AllResources() {
			granted := false
			for _, a := range AllActions() {
				granted = granted || Can(role, res, a)
			}
			if granted && ScopeFor(role, res) == ScopeNone {
				t.Errorf("%s holds %s but reaches no rows", role, res)
			}
		}
	}
}

func TestZeroValuesDeny(t *testing.T) {
	unknown := []entities.Role{"", "root", "ADMIN"}
	for _, role := range unknown {
		if Can(role, ResNote, ActionRead) {
			t.Errorf("unknown role %q was granted", role)
		}
		if ScopeFor(role, ResNote) != ScopeNone {
			t.Errorf("unknown role %q has reach", role)
		}
		if d := Decide(Subject{UserID: 1, Role: role}, ResNote, ActionRead, ResourceRef{OwnerUserID: 1}); d.Allowed {
			t.Errorf("Decide allowed unknown role %q", role)
		}
		if HasCapability(role, CapUsersRoleUpdate) {
			t.Errorf("unknown role %q holds a capability", role)
		}
	}
	if Can(entities.RoleAdmin, "made.up", ActionRead) {
		t.Error("unknown resource was granted")
	}
	if Can(entities.RoleAdmin, ResNote, "explode") {
		t.Error("unknown action was granted")
	}
	if d := Decide(Subject{}, ResNote, ActionRead, ResourceRef{}); d.Allowed {
		t.Error("the empty subject was allowed")
	}
}

func TestDecideScope(t *testing.T) {
	owner := Subject{UserID: 7, Role: entities.RoleUser}
	cases := []struct {
		name   string
		s      Subject
		a      Action
		ref    ResourceRef
		allow  bool
		reason DenyReason
	}{
		{"user reads own", owner, ActionRead, ResourceRef{OwnerUserID: 7}, true, ReasonNone},
		{"user reads another's", owner, ActionRead, ResourceRef{OwnerUserID: 8}, false, ReasonOutOfScope},
		{"zero owner never matches", Subject{UserID: 0, Role: entities.RoleUser}, ActionRead, ResourceRef{}, false, ReasonOutOfScope},
		{"support reads any", Subject{UserID: 2, Role: entities.RoleSupport}, ActionRead, ResourceRef{OwnerUserID: 7}, true, ReasonNone},
		{"support cannot write", Subject{UserID: 2, Role: entities.RoleSupport}, ActionUpdate, ResourceRef{OwnerUserID: 2}, false, ReasonNoGrant},
		{"admin updates any", Subject{UserID: 3, Role: entities.RoleAdmin}, ActionUpdate, ResourceRef{OwnerUserID: 7}, true, ReasonNone},
	}
	for _, tc := range cases {
		d := Decide(tc.s, ResNote, tc.a, tc.ref)
		if d.Allowed != tc.allow || d.Reason != tc.reason {
			t.Errorf("%s: got %+v", tc.name, d)
		}
	}
}

func TestUpdatingUsersDoesNotImplyChangingRoles(t *testing.T) {
	saved := matrix[entities.RoleSupport][ResAdminUsers]
	matrix[entities.RoleSupport][ResAdminUsers] = mCRUD
	defer func() { matrix[entities.RoleSupport][ResAdminUsers] = saved }()

	if HasCapability(entities.RoleSupport, CapUsersRoleUpdate) {
		t.Fatal("users CRUD must not grant role changes")
	}
	if CanAssignRole(entities.RoleSupport, entities.RoleUser) {
		t.Fatal("users CRUD must not allow role assignment")
	}
}

func TestRoleAssignment(t *testing.T) {
	for _, target := range entities.AllRoles() {
		if !CanAssignRole(entities.RoleAdmin, target) {
			t.Errorf("admin cannot grant %s", target)
		}
		for _, assigner := range []entities.Role{entities.RoleUser, entities.RoleSupport} {
			if CanAssignRole(assigner, target) {
				t.Errorf("%s granted %s", assigner, target)
			}
		}
	}
	if CanAssignRole(entities.RoleAdmin, "root") {
		t.Error("granted a role that does not exist")
	}
	if CanChangeRoleFrom(entities.RoleSupport, entities.RoleAdmin) {
		t.Error("support changed an admin's role")
	}
	if !CanChangeRoleFrom(entities.RoleAdmin, entities.RoleAdmin) {
		t.Error("admin must be able to change another admin's role")
	}
}

// The guard is a backstop, and this proves it: an unsafe delegation authored by
// mistake is still refused, while a safe target from the same mistake still works.
func TestEscalationGuardCatchesAnUnsafeAuthoredDelegation(t *testing.T) {
	holders := capabilities[CapUsersRoleUpdate]
	holders[entities.RoleSupport] = struct{}{}
	assignableRoles[entities.RoleSupport] = []entities.Role{entities.RoleAdmin, entities.RoleUser}
	defer func() {
		delete(holders, entities.RoleSupport)
		delete(assignableRoles, entities.RoleSupport)
	}()

	if CanAssignRole(entities.RoleSupport, entities.RoleAdmin) {
		t.Fatal("the guard let support grant admin")
	}
	saved := matrix[entities.RoleSupport][ResNote]
	matrix[entities.RoleSupport][ResNote] = mCRUD
	defer func() { matrix[entities.RoleSupport][ResNote] = saved }()
	if !CanAssignRole(entities.RoleSupport, entities.RoleUser) {
		t.Fatal("the guard over-blocked a target holding nothing the assigner lacks")
	}
}

func TestDecideCapabilityDeniesAllCapabilitiesWhileImpersonating(t *testing.T) {
	imp := uint(99)
	s := Subject{UserID: 3, Role: entities.RoleAdmin, Impersonator: &imp}
	for _, c := range []Capability{CapUsersRoleUpdate, CapUsersImpersonate} {
		if d := DecideCapability(s, c); d.Allowed || d.Reason != ReasonImpersonation {
			t.Errorf("%s inside login-as: %+v", c, d)
		}
	}
	s.Impersonator = nil
	if d := DecideCapability(s, CapUsersRoleUpdate); !d.Allowed {
		t.Errorf("without impersonation: %+v", d)
	}
	if d := DecideCapability(Subject{UserID: 1, Role: entities.RoleUser}, CapUsersRoleUpdate); d.Reason != ReasonNoGrant {
		t.Errorf("no grant: %+v", d)
	}
}

func TestServedPermissionsMatchTheMatrix(t *testing.T) {
	got := PermissionsFor(entities.RoleSupport)
	want := []Permission{"admin.users:read", "note:read"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v", got)
	}
	if caps := CapabilitiesFor(entities.RoleUser); len(caps) != 0 {
		t.Fatalf("user capabilities = %v", caps)
	}
	if caps := CapabilitiesFor(entities.RoleAdmin); len(caps) != 2 {
		t.Fatalf("admin capabilities = %v", caps)
	}
	if s := ScopesFor(entities.RoleUser); s[ResNote] != "own" || s[ResAdminUsers] != "none" {
		t.Fatalf("scopes = %v", s)
	}
}
