package repo

import (
	"fmt"
	"regexp"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"gorm.io/gorm"
)

// safeIdentifier matches a column / association identifier: a leading
// letter/underscore, optionally dotted (e.g. "users.email", "Organization.Owner").
// Filter keys, sort fields, selected columns and preloads are interpolated into
// SQL as identifiers (not parameterized), so they MUST be validated against this
// allowlist to prevent SQL injection when any of these originate from request
// input. Anything that fails the pattern aborts the query.
var safeIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$`)

func validIdentifier(s string) bool {
	return safeIdentifier.MatchString(s)
}

// normalizePagination returns sane defaults for page and pageSize values.
func normalizePagination(opts store.QueryOpts) (page, pageSize int) {
	page = opts.Page
	pageSize = opts.PageSize

	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	return
}

// apply where, filters, sorting, selects, and preloads from QueryOpts to the gorm DB instance.
func applyQueryOptsBase(db *gorm.DB, opts store.QueryOpts) *gorm.DB {
	// simple filters: column = value. Column names are identifiers and are
	// validated; values are always parameterized.
	for col, val := range opts.Filters {
		if !validIdentifier(col) {
			_ = db.AddError(fmt.Errorf("invalid filter column %q", col))
			return db
		}
		db = db.Where(col+" = ?", val)
	}

	// advanced WHERE clauses (caller-controlled; do not pass untrusted Expr)
	for _, c := range opts.Where {
		db = db.Where(c.Expr, c.Args...)
	}

	// select specific columns
	for _, col := range opts.Select {
		if !validIdentifier(col) {
			_ = db.AddError(fmt.Errorf("invalid select column %q", col))
			return db
		}
	}
	if len(opts.Select) > 0 {
		db = db.Select(opts.Select)
	}

	// preloads (association names)
	for _, p := range opts.Preloads {
		if !validIdentifier(p) {
			_ = db.AddError(fmt.Errorf("invalid preload %q", p))
			return db
		}
		db = db.Preload(p)
	}

	// sorting
	for _, s := range opts.Sort {
		if !validIdentifier(s.Field) {
			_ = db.AddError(fmt.Errorf("invalid sort field %q", s.Field))
			return db
		}
		dir := "ASC"
		if s.Desc {
			dir = "DESC"
		}
		db = db.Order(s.Field + " " + dir)
	}

	return db
}
