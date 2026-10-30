// Package scopequery derives a list query's WHERE clause from the actor's authored scope,
// which keeps out-of-reach rows out of the result even if a handler omits a filter. Checks
// on a single row use authz.Decide.
package scopequery

import (
	"fmt"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
)

// impossible is a clause no row satisfies. Denial has to mean an empty result, and must
// never fall through to a query with no condition at all.
var impossible = store.Clause{Expr: "1 = 0"}

// ForOwned returns the clause limiting a list of res to what s may read, for a table
// whose owner is ownerColumn. ownerColumn is written by the caller, never request input.
func ForOwned(s authz.Subject, res authz.Resource, ownerColumn string) store.Clause {
	if !authz.Can(s.Role, res, authz.ActionRead) {
		return impossible
	}
	switch authz.ScopeFor(s.Role, res) {
	case authz.ScopeGlobal:
		return store.Clause{Expr: "1 = 1"}
	case authz.ScopeOwn:
		if s.UserID == 0 {
			return impossible
		}
		return store.Clause{Expr: fmt.Sprintf("%s = ?", ownerColumn), Args: []any{s.UserID}}
	}
	return impossible
}
