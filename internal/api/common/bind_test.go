package apicommon

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func bindRecorder(t *testing.T, err error) (*httptest.ResponseRecorder, *gin.Context) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	RespondBindError(c, err)
	return w, c
}

func TestRespondBindErrorHidesDecoderText(t *testing.T) {
	w, c := bindRecorder(t, errors.New("json: cannot unmarshal string into Go struct field"))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "Go struct") {
		t.Fatalf("decoder text reached the client: %s", w.Body.String())
	}
	if len(c.Errors) != 1 || !strings.Contains(c.Errors.String(), "Go struct") {
		t.Fatal("decoder text must reach the request log through c.Error")
	}
}

func TestRespondBindErrorOversizeBodyIs413(t *testing.T) {
	w, _ := bindRecorder(t, &http.MaxBytesError{Limit: 10})

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", w.Code)
	}
	var body Response[any]
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "payload_too_large" {
		t.Fatalf("code = %q", body.Error)
	}
}
