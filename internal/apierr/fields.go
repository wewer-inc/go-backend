package apierr

import "net/http"

// Shared codes for a request of the wrong shape. Clients pick their translation from
// the code, so a code keeps a single meaning across modules, and the field concerned
// is named in Details.
const (
	CodeInvalidRequestBody = "invalid_request_body"
	CodeFieldRequired      = "field_required"
	CodeInvalidField       = "invalid_field"
	CodePayloadTooLarge    = "payload_too_large"

	// MessageInvalidRequestBody is the fixed response text when a body is unreadable.
	// Decoder errors mention Go types and byte offsets, so only the logs get those.
	MessageInvalidRequestBody = "request body is not valid"
)

// Why a single field was refused, one code per entry of a per-field error's details.
// These do not change between releases, so clients can translate from them and treat
// the English message next to each as a fallback.
const (
	FieldCodeRequired     = "required"
	FieldCodeUnknownField = "unknown_field"
	FieldCodeNotAllowed   = "not_allowed"

	FieldCodeInvalidValue  = "invalid_value"
	FieldCodeInvalidFormat = "invalid_format"
	FieldCodeInvalidType   = "invalid_type"

	FieldCodeTooLong    = "too_long"
	FieldCodeTooMany    = "too_many"
	FieldCodeOutOfRange = "out_of_range"

	FieldCodeConflict  = "conflict"
	FieldCodeDuplicate = "duplicate"
)

// FieldDetails names the field behind a field_required or invalid_field error, using the
// request's own spelling, which may be a JSON key, query parameter or dotted path.
type FieldDetails struct {
	Field string `json:"field"`
}

// InvalidRequestBody reports an unreadable or undecodable body with a 400. The optional
// cause goes to the logs and nowhere else.
func InvalidRequestBody(cause error) *APIError {
	return &APIError{
		Code: CodeInvalidRequestBody, Message: MessageInvalidRequestBody,
		Status: http.StatusBadRequest, Err: cause,
	}
}

// PayloadTooLarge is the 413 for a body over the configured cap. cause may be nil.
func PayloadTooLarge(cause error) *APIError {
	return &APIError{
		Code: CodePayloadTooLarge, Message: "the payload is too large",
		Status: http.StatusRequestEntityTooLarge, Err: cause,
	}
}

// FieldRequired reports a mandatory field that was omitted or left empty with a 400.
func FieldRequired(field, message string) *APIError {
	return &APIError{
		Code: CodeFieldRequired, Message: message, Status: http.StatusBadRequest,
		Details: FieldDetails{Field: field},
	}
}

// InvalidField reports a field with an unusable type, format or range with a 400.
func InvalidField(field, message string) *APIError {
	return &APIError{
		Code: CodeInvalidField, Message: message, Status: http.StatusBadRequest,
		Details: FieldDetails{Field: field},
	}
}
