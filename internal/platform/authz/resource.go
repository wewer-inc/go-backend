package authz

// Action is a CRUD verb. Anything that is not a CRUD verb is a Capability.
type Action string

const (
	ActionCreate Action = "create"
	ActionRead   Action = "read"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

// AllActions returns the CRUD verbs. The tests iterate this.
func AllActions() []Action {
	return []Action{ActionCreate, ActionRead, ActionUpdate, ActionDelete}
}

// Resource is one authorization surface.
type Resource string

const (
	ResNote       Resource = "note"
	ResAdminUsers Resource = "admin.users"
	ResAdminAudit Resource = "admin.audit"
)

// AllResources returns every resource. The completeness tests iterate this.
func AllResources() []Resource {
	return []Resource{ResNote, ResAdminUsers, ResAdminAudit}
}

// Permission is a resource:action pair, in the form served to clients.
type Permission string

// Perm builds the Permission for a resource and action.
func Perm(res Resource, a Action) Permission {
	return Permission(string(res) + ":" + string(a))
}
