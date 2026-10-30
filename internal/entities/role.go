package entities

type Role string

const (
	RoleUser    Role = "user"
	RoleAdmin   Role = "admin"
	RoleSupport Role = "support"
)

// AllRoles lists the roles the product offers. The authz tests walk this list and check
// each policy table against it, so a new role with no policy fails in CI and never gets
// the chance to grant or deny anything by accident in production.
func AllRoles() []Role {
	return []Role{RoleUser, RoleSupport, RoleAdmin}
}

// Valid reports whether r appears in AllRoles.
func (r Role) Valid() bool {
	for _, known := range AllRoles() {
		if r == known {
			return true
		}
	}
	return false
}
