package store

// SortField represents a single ORDER BY clause
type SortField struct {
	Field string
	Desc  bool
}

// Clause represents a single advanced SQL WHERE condition with its expression
// and arguments.
type Clause struct {
	Expr string
	Args []any
}

// QueryOpts encapsulates filters, sorting, pagination, preloading, and
// selection options for querying the store.
type QueryOpts struct {
	// Simple equality filters: column => value (e.g., "status" => "active")
	Filters map[string]any

	// Advanced filtering conditions (Expr + Args)
	Where []Clause

	// Sorting options
	Sort []SortField

	// Pagination (1-based indexing)
	Page     int
	PageSize int

	// GORM preloads, e.g. []string{"Organization", "Photos"}
	Preloads []string

	// Explicit columns to select
	Select []string

	// Unscoped includes soft-deleted rows. Reach for it only on a read that must
	// still find a row after it was soft-deleted, never on a write path.
	Unscoped bool
}

// PageInfo contains pagination metadata for query results
type PageInfo struct {
	Page     int
	PageSize int
	Total    int64
	HasNext  bool
}
