package authz

import "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"

// Capability is a named power that is not a CRUD verb.
type Capability string

const (
	// CapUsersRoleUpdate changes a user's role. Deliberately not implied by
	// admin.users:update, so "may edit a user" cannot become "may promote a user".
	CapUsersRoleUpdate Capability = "admin.users.role:update"
	// CapUsersImpersonate lets an admin open a session as another user ("login as").
	CapUsersImpersonate Capability = "admin.users:impersonate"
	// CapUsersMFAReset clears another user's second factor. Separate from admin.users:update
	// because stripping someone's MFA is a step toward taking over their account.
	CapUsersMFAReset Capability = "admin.users.mfa:reset"
)

// AllCapabilities is the full list of capabilities, which the completeness tests walk.
func AllCapabilities() []Capability {
	return []Capability{CapUsersRoleUpdate, CapUsersImpersonate, CapUsersMFAReset}
}

// capabilities maps each capability to the roles holding it. An absent role does not.
var capabilities = map[Capability]map[entities.Role]struct{}{
	CapUsersRoleUpdate:  {entities.RoleAdmin: {}},
	CapUsersImpersonate: {entities.RoleAdmin: {}},
	CapUsersMFAReset:    {entities.RoleAdmin: {}},
}

// impersonationBarred is the set of capabilities denied to a "login as" session regardless
// of the role it is wearing. Such a session exists to observe an account, and these powers
// would let the impersonator raise privileges or open further sessions under another name.
var impersonationBarred = map[Capability]struct{}{
	CapUsersRoleUpdate:  {},
	CapUsersImpersonate: {},
	CapUsersMFAReset:    {},
}

// ImpersonationBars reports whether c is off limits to a "login as" session.
func ImpersonationBars(c Capability) bool {
	_, barred := impersonationBarred[c]
	return barred
}
