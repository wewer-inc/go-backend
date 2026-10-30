// Package authz makes role-based access decisions. Everything in it serves one question:
// is a given subject allowed to perform an action on a resource.
//
// # Pure functions only
//
// The package touches neither a database nor Gin, keeps no logger or clock, and does no
// I/O. An exported function's result depends on its arguments alone, so tests can check
// the role matrix one cell at a time. Policy sits in the source and not in a table
// because a role should gain power only through reviewed code, and git history then shows
// each such change beyond the reach of anyone holding an admin session.
//
// # Denial is the default
//
// Zero values deny. A role with no mapping, a resource nobody listed, a Subject without
// a role and an absent scope entry all come back as a denial and never as an unfiltered
// result. A new role or resource with no policy written fails this package's completeness
// tests, which catches the gap before it can grant or deny anything in production.
//
// # Two questions, two layers
//
//   - Route: "may this role ever do this?" answered by Can or HasCapability, through
//     middleware.RequirePermission and RequireCapability. No row is in hand yet.
//   - Row: "may this subject do this to THIS row?" answered by Decide with a
//     ResourceRef in the service or handler, and by platform/scopequery on list
//     queries, where it stands in for any filter a handler left out.
//
// # Actions versus capabilities
//
// An Action is a CRUD verb. Anything that is not ("may approve", "may log in as
// another user") is a Capability. Modelling those as CRUD would make updating a user
// imply the power to change their role, which is an escalation path.
//
// # Adapting it
//
// Add a Resource in resource.go, a row in matrix.go and an entry in scope.go for each
// role. The tests then tell you what else is missing.
package authz
