package authz

import (
	"sort"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
)

// Subject describes the caller for one decision. Middleware fills it from the user's row on
// every request and takes nothing from the token, which is why losing a role bites at once
// and does not have to wait out the token's lifetime.
type Subject struct {
	UserID uint
	Role   entities.Role
	// Impersonator is set only inside a "login as" session, to the admin who opened it.
	Impersonator *uint
}

// ResourceRef is the row being acted on. Build it with the row's real owner.
type ResourceRef struct {
	OwnerUserID uint
}

// DenyReason is why a decision denied. For logs and metrics; never shown to a client
// verbatim. A closed set, so it is safe as a metric label.
type DenyReason string

const (
	ReasonNone          DenyReason = ""
	ReasonNoGrant       DenyReason = "no_grant"
	ReasonOutOfScope    DenyReason = "out_of_scope"
	ReasonImpersonation DenyReason = "impersonation_barred"
)

// Decision is the answer to one authorization question.
type Decision struct {
	Allowed bool
	Reason  DenyReason
}

func allow() Decision            { return Decision{Allowed: true} }
func deny(r DenyReason) Decision { return Decision{Reason: r} }

// Can reports whether the matrix grants role the action on res, without regard to any row.
func Can(role entities.Role, res Resource, a Action) bool {
	return matrix[role][res].has(a)
}

// HasCapability looks up who holds c and reports whether role is among them.
func HasCapability(role entities.Role, c Capability) bool {
	_, ok := capabilities[c][role]
	return ok
}

// Decide answers whether the subject may take the action on this row.
func Decide(s Subject, res Resource, a Action, ref ResourceRef) Decision {
	if !Can(s.Role, res, a) {
		return deny(ReasonNoGrant)
	}
	switch ScopeFor(s.Role, res) {
	case ScopeGlobal:
		return allow()
	case ScopeOwn:
		// A zero owner or subject is unknown, and unknown never matches.
		if s.UserID != 0 && ref.OwnerUserID == s.UserID {
			return allow()
		}
	}
	return deny(ReasonOutOfScope)
}

// DecideCapability answers whether the subject may exercise a capability now, which
// adds the impersonation bar to the role's grant.
func DecideCapability(s Subject, c Capability) Decision {
	if !HasCapability(s.Role, c) {
		return deny(ReasonNoGrant)
	}
	if s.Impersonator != nil && ImpersonationBars(c) {
		return deny(ReasonImpersonation)
	}
	return allow()
}

// assignableRoles is the authored delegation graph: who may grant what. The escalation
// guard below is a separate backstop, so widening this table without thinking it
// through cannot silently open an escalation path.
var assignableRoles = map[entities.Role][]entities.Role{
	entities.RoleAdmin: {entities.RoleUser, entities.RoleSupport, entities.RoleAdmin},
}

// CanAssignRole applies two independent tests to a proposed grant, and both must pass:
// target is listed for assigner in the delegation graph, and the escalation guard finds no
// sensitive power in target that assigner is missing.
func CanAssignRole(assigner, target entities.Role) bool {
	if !HasCapability(assigner, CapUsersRoleUpdate) || !target.Valid() {
		return false
	}
	authored := false
	for _, r := range assignableRoles[assigner] {
		if r == target {
			authored = true
			break
		}
	}
	return authored && withinEscalationGuard(assigner, target)
}

// withinEscalationGuard requires the assigner to hold every sensitive power of the
// target: writes to any resource, and every capability.
func withinEscalationGuard(assigner, target entities.Role) bool {
	for _, res := range AllResources() {
		for _, a := range []Action{ActionCreate, ActionUpdate, ActionDelete} {
			if Can(target, res, a) && !Can(assigner, res, a) {
				return false
			}
		}
	}
	for _, c := range AllCapabilities() {
		if HasCapability(target, c) && !HasCapability(assigner, c) {
			return false
		}
	}
	return true
}

// CanChangeRoleFrom protects the role a user already holds. CanAssignRole only looks at
// the new role, so on its own it would let someone allowed to hand out a lesser role use
// that to demote a user who outranks them.
func CanChangeRoleFrom(assigner, current entities.Role) bool {
	if !HasCapability(assigner, CapUsersRoleUpdate) {
		return false
	}
	return withinEscalationGuard(assigner, current)
}

// PermissionsFor returns the role's permissions, sorted, for serving to clients.
func PermissionsFor(role entities.Role) []Permission {
	out := []Permission{}
	for _, res := range AllResources() {
		for _, a := range AllActions() {
			if Can(role, res, a) {
				out = append(out, Perm(res, a))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CapabilitiesFor returns the role's capabilities, sorted, for serving to clients.
func CapabilitiesFor(role entities.Role) []Capability {
	out := []Capability{}
	for _, c := range AllCapabilities() {
		if HasCapability(role, c) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ScopesFor returns the role's reach per resource, for serving to clients.
func ScopesFor(role entities.Role) map[Resource]string {
	out := make(map[Resource]string, len(AllResources()))
	for _, res := range AllResources() {
		out[res] = ScopeFor(role, res).String()
	}
	return out
}
