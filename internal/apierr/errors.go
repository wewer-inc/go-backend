package apierr

import (
	"fmt"
	"net/http"
)

// APIError is a structured error returned by handlers.
type APIError struct {
	Code    string
	Message string
	Status  int
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Sentinel constructors.

func NotFound(code, message string) *APIError {
	return &APIError{Code: code, Message: message, Status: http.StatusNotFound}
}

func BadRequest(code, message string) *APIError {
	return &APIError{Code: code, Message: message, Status: http.StatusBadRequest}
}

func Unauthorized(message string) *APIError {
	return &APIError{Code: "unauthorized", Message: message, Status: http.StatusUnauthorized}
}

func Forbidden(message string) *APIError {
	return &APIError{Code: "forbidden", Message: message, Status: http.StatusForbidden}
}

func Internal(message string) *APIError {
	return &APIError{Code: "internal_error", Message: message, Status: http.StatusInternalServerError}
}

func Conflict(code, message string) *APIError {
	return &APIError{Code: code, Message: message, Status: http.StatusConflict}
}
