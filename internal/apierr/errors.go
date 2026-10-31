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
	// Details holds machine-readable context that is sent to the client, for
	// example the per-field errors of a rejected save. It leaves the server, which
	// Err never does, so keep it to what the caller is entitled to see: field names
	// and codes, not stored values or internal causes.
	Details any
	// Err is the failure behind this error, if any. Logs see it and responses do
	// not. InternalErr is the usual way to set it.
	Err error
}

// WithDetails attaches details to a clone of e and leaves e untouched. Package-level
// error values are shared by concurrent requests, so setting the field in place could
// expose what one caller sent to whoever is answered next.
func (e *APIError) WithDetails(details any) *APIError {
	clone := *e
	clone.Details = details
	return &clone
}

func (e *APIError) Error() string {
	text := fmt.Sprintf("%s: %s", e.Code, e.Message)
	if e.Err == nil {
		return text
	}
	return fmt.Sprintf("%s: %v", text, e.Err)
}

// Unwrap returns the cause, which lets errors.Is and errors.As look behind e.
func (e *APIError) Unwrap() error { return e.Err }

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

// UnauthorizedCode builds a 401 whose machine code the caller picks.
func UnauthorizedCode(code, message string) *APIError {
	return &APIError{Code: code, Message: message, Status: http.StatusUnauthorized}
}

// ForbiddenCode builds a 403 whose machine code the caller picks.
func ForbiddenCode(code, message string) *APIError {
	return &APIError{Code: code, Message: message, Status: http.StatusForbidden}
}

// UnprocessableEntity builds a 422: the request parses and the caller is allowed to
// make it, but the server declines to produce the result. Use BadRequest when the
// request itself is malformed.
func UnprocessableEntity(code, message string) *APIError {
	return &APIError{Code: code, Message: message, Status: http.StatusUnprocessableEntity}
}

// TooManyRequests builds a 429 for a caller that is locked out or throttled.
func TooManyRequests(code, message string) *APIError {
	return &APIError{Code: code, Message: message, Status: http.StatusTooManyRequests}
}

// ServiceUnavailable builds a 503 for a feature this deployment has not set up, such
// as one whose dependency is unwired. The request was fine and nothing broke, so it
// should stay clear of the alerting a 500 sets off.
func ServiceUnavailable(code, message string) *APIError {
	return &APIError{Code: code, Message: message, Status: http.StatusServiceUnavailable}
}

// InternalErr builds a 500 that keeps its cause for the logs while the client sees
// only message. The cause is logged as is, so its text must not embed a secret.
func InternalErr(cause error, message string) *APIError {
	return &APIError{Code: "internal_error", Message: message, Status: http.StatusInternalServerError, Err: cause}
}

func Internal(message string) *APIError {
	return &APIError{Code: "internal_error", Message: message, Status: http.StatusInternalServerError}
}

func Conflict(code, message string) *APIError {
	return &APIError{Code: code, Message: message, Status: http.StatusConflict}
}
