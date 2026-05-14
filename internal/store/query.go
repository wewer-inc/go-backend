package store

// SortField represents a single ORDER BY clause
type SortField struct {
	Field string
	Desc  bool
}

// (Advanced WHERE condition)
// Clause represents a single SQL clause with its expression and arguments
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
}

// PageInfo contains pagination metadata for query results
type PageInfo struct {
	Page     int
	PageSize int
	Total    int64
	HasNext  bool
}
