package apierr

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestInternalErrKeepsCauseForLogsOnly(t *testing.T) {
	cause := errors.New("pq: connection refused")
	e := InternalErr(cause, "could not save")

	if e.Message != "could not save" {
		t.Fatalf("message = %q; the cause must not reach the client-visible message", e.Message)
	}
	if !errors.Is(e, cause) {
		t.Fatal("errors.Is must reach the wrapped cause")
	}
	if !strings.Contains(e.Error(), "connection refused") {
		t.Fatalf("Error() = %q; logs need the cause", e.Error())
	}
}

func TestWithDetailsCopiesRatherThanMutates(t *testing.T) {
	shared := BadRequest("bad", "bad")
	withDetails := shared.WithDetails(map[string]string{"field": "email"})

	if shared.Details != nil {
		t.Fatal("WithDetails mutated the shared error")
	}
	if withDetails.Details == nil {
		t.Fatal("copy lost its details")
	}
}

func TestFieldErrorsCarryTheFieldName(t *testing.T) {
	for _, e := range []*APIError{FieldRequired("email", "required"), InvalidField("email", "invalid")} {
		d, ok := e.Details.(FieldDetails)
		if !ok || d.Field != "email" {
			t.Fatalf("%s details = %#v", e.Code, e.Details)
		}
		if e.Status != http.StatusBadRequest {
			t.Fatalf("%s status = %d", e.Code, e.Status)
		}
	}
}

func TestPayloadTooLargeStatus(t *testing.T) {
	if got := PayloadTooLarge(nil).Status; got != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", got)
	}
}

func TestInvalidRequestBodyHidesDecoderText(t *testing.T) {
	e := InvalidRequestBody(errors.New("json: cannot unmarshal string into Go struct field"))
	if strings.Contains(e.Message, "Go struct") {
		t.Fatalf("decoder text reached the message: %q", e.Message)
	}
	if !strings.Contains(e.Error(), "Go struct") {
		t.Fatal("decoder text must still reach the logs")
	}
}
