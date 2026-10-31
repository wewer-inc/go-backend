package users

// ChangeRoleRequest is the body of PATCH /v1/admin/users/:uuid/role.
type ChangeRoleRequest struct {
	Role string `json:"role" binding:"required"`
}

// RoleResponse is the user's role after the change.
type RoleResponse struct {
	UUID         string `json:"uuid"`
	PlatformRole string `json:"platform_role"`
}
