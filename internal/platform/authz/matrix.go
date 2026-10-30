package authz

import "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"

type mask uint8

const (
	opCreate mask = 1 << iota
	opRead
	opUpdate
	opDelete
)

const (
	mNone mask = 0
	mR    mask = opRead
	mCRUD mask = opCreate | opRead | opUpdate | opDelete
)

var actionBits = map[Action]mask{
	ActionCreate: opCreate,
	ActionRead:   opRead,
	ActionUpdate: opUpdate,
	ActionDelete: opDelete,
}

// has reports whether the action's bit is set. An action missing from actionBits has no
// bit, so it always reads as not granted.
func (m mask) has(a Action) bool {
	return m&actionBits[a] != 0
}

// matrix is the role to resource grant table. Every role names every resource,
// including explicit denials, so a reader never has to infer one from an absence.
// TestMatrixFixture asserts it cell by cell.
var matrix = map[entities.Role]map[Resource]mask{
	entities.RoleUser: {
		ResNote:       mCRUD,
		ResAdminUsers: mNone,
		ResAdminAudit: mNone,
	},
	entities.RoleSupport: {
		ResNote:       mR,
		ResAdminUsers: mR,
		ResAdminAudit: mNone,
	},
	entities.RoleAdmin: {
		ResNote:       mCRUD,
		ResAdminUsers: mCRUD,
		ResAdminAudit: mR,
	},
}
