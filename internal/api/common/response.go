package apicommon

// Response is the standard single-item / message envelope returned by all handlers.
// On failure "error" holds the machine code and "message" the text, and "details" is
// added only for an error that has some for the client to use (apierr.APIError.Details).
type Response[T any] struct {
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	Details any    `json:"details,omitempty"`
	Data    *T     `json:"data,omitempty"`
}

// Pagination is the metadata returned alongside a list response.
type Pagination struct {
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
	Total    int64 `json:"total"`
	HasNext  bool  `json:"has_next"`
}

// PaginatedResponse is the standard envelope for list endpoints, keeping list
// responses consistent with the single-item Response envelope.
type PaginatedResponse[T any] struct {
	Error string      `json:"error,omitempty"`
	Data  []T         `json:"data"`
	Page  *Pagination `json:"page,omitempty"`
}
