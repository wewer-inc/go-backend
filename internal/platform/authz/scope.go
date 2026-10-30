package authz

import "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"

// Scope is which rows of a resource a role reaches. It is a separate axis from the
// action set: a role may update notes, and scope decides whose.
//
// ScopeNone comes first so that it is the zero value, which makes an absent entry a denial.
type Scope uint8

const (
	ScopeNone   Scope = iota // deny
	ScopeOwn                 // only the actor's own rows
	ScopeGlobal              // all rows
)

func (s Scope) String() string {
	switch s {
	case ScopeOwn:
		return "own"
	case ScopeGlobal:
		return "global"
	default:
		return "none"
	}
}

var scopes = map[entities.Role]map[Resource]Scope{
	entities.RoleUser: {
		ResNote:       ScopeOwn,
		ResAdminUsers: ScopeNone,
		ResAdminAudit: ScopeNone,
	},
	entities.RoleSupport: {
		ResNote:       ScopeGlobal,
		ResAdminUsers: ScopeGlobal,
		ResAdminAudit: ScopeNone,
	},
	entities.RoleAdmin: {
		ResNote:       ScopeGlobal,
		ResAdminUsers: ScopeGlobal,
		ResAdminAudit: ScopeGlobal,
	},
}

// ScopeFor returns the role's reach over a resource. Unknown input is ScopeNone.
func ScopeFor(role entities.Role, res Resource) Scope {
	return scopes[role][res]
}
