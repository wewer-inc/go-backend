package repo

import (
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"gorm.io/gorm"
)

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
	// simple filters: column = value
	for col, val := range opts.Filters {
		db = db.Where(col+" = ?", val)
	}

	// advanced WHERE clauses
	for _, c := range opts.Where {
		db = db.Where(c.Expr, c.Args...)
	}

	// select specific columns
	if len(opts.Select) > 0 {
		db = db.Select(opts.Select)
	}

	// preloads
	for _, p := range opts.Preloads {
		db = db.Preload(p)
	}

	// sorting
	for _, s := range opts.Sort {
		dir := "ASC"
		if s.Desc {
			dir = "DESC"
		}
		db = db.Order(s.Field + " " + dir)
	}

	return db
}
