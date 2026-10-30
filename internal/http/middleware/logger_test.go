package middleware

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/reqid"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

func logRouter(buf *bytes.Buffer) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(RequestIDMiddleware(), Logger(zerolog.New(buf)))
	return r
}

func TestLoggerRecordsTheCauseOfAFailedRequest(t *testing.T) {
	var buf bytes.Buffer
	r := logRouter(&buf)
	r.GET("/things/:id", func(c *gin.Context) {
		_ = c.Error(apierr.InternalErr(errors.New("db down"), "something went wrong"))
		c.Status(http.StatusInternalServerError)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/things/42", nil))

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log line is not JSON: %v (%s)", err, buf.String())
	}
	if line["level"] != "error" || line["route"] != "/things/:id" || line["error_code"] != "internal_error" {
		t.Fatalf("line = %v", line)
	}
	if line["request_id"] != w.Header().Get("X-Request-ID") {
		t.Fatalf("request_id %v does not match the response header", line["request_id"])
	}
	if _, ok := line["client_ip"]; !ok {
		t.Fatal("a failed request should log the client IP")
	}
}

func TestLoggerOmitsClientIPOnSuccess(t *testing.T) {
	var buf bytes.Buffer
	r := logRouter(&buf)
	r.GET("/ok", func(c *gin.Context) { c.Status(http.StatusOK) })

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ok", nil))

	if bytes.Contains(buf.Bytes(), []byte("client_ip")) {
		t.Fatalf("healthy line carries the client IP: %s", buf.String())
	}
}

func TestLoggerSkipsHealthyProbesOnly(t *testing.T) {
	var buf bytes.Buffer
	r := logRouter(&buf)
	status := http.StatusOK
	r.GET("/ready", func(c *gin.Context) { c.Status(status) })

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ready", nil))
	if buf.Len() != 0 {
		t.Fatalf("healthy probe was logged: %s", buf.String())
	}

	status = http.StatusServiceUnavailable
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/ready", nil))
	if buf.Len() == 0 {
		t.Fatal("a failing probe must be logged")
	}
}

func TestHandlerSeesTheRequestIDFromTheResponseHeader(t *testing.T) {
	var buf bytes.Buffer
	r := logRouter(&buf)
	var seen string
	r.GET("/x", func(c *gin.Context) { seen = reqid.FromContext(c.Request.Context()) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

	if seen == "" || seen != w.Header().Get("X-Request-ID") {
		t.Fatalf("context id %q, header %q", seen, w.Header().Get("X-Request-ID"))
	}
}
