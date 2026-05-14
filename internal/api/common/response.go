package apicommon

type Response[T any] struct {
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
	Data    *T     `json:"data,omitempty"`
}
