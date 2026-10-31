package middleware

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func bodyRouter(limit int64, exempt ...string) (*gin.Engine, *string) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(BodyLimit(limit), RejectNULBytes(exempt...))
	seen := new(string)
	r.POST("/x", func(c *gin.Context) {
		b, _ := io.ReadAll(c.Request.Body)
		*seen = string(b)
		c.Status(http.StatusOK)
	})
	return r, seen
}

func post(r http.Handler, contentType, body string, chunked bool) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if chunked {
		req.ContentLength = -1
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestBodyLimitRefusesDeclaredOversizeBeforeReading(t *testing.T) {
	r, seen := bodyRouter(4)
	w := post(r, "application/json", `{"a":1}`, false)
	if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), "payload_too_large") {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	if *seen != "" {
		t.Fatal("handler must not run")
	}
}

func TestBodyLimitCatchesUndeclaredOversize(t *testing.T) {
	r, _ := bodyRouter(4)
	w := post(r, "application/json", `{"a":1}`, true)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", w.Code)
	}
}

func TestBodyLimitZeroDisablesTheCap(t *testing.T) {
	r, seen := bodyRouter(0)
	if w := post(r, "application/json", `{"a":1}`, false); w.Code != http.StatusOK || *seen != `{"a":1}` {
		t.Fatalf("status %d seen %q", w.Code, *seen)
	}
}

func TestBodyFilterCatchesEveryNULSpelling(t *testing.T) {
	cases := map[string]struct {
		contentType, body string
		want              int
	}{
		"clean json is passed through":             {"application/json", `{"a":"b"}`, http.StatusOK},
		"lowercase json escape":                    {"application/json", `{"a":"b\u0000c"}`, http.StatusBadRequest},
		"uppercase json escape":                    {"application/json", `{"a":"b\U0000c"}`, http.StatusBadRequest},
		"literal zero byte":                        {"application/json", "{\"a\":\"b\x00c\"}", http.StatusBadRequest},
		"a multipart label does not skip the scan": {"multipart/form-data; boundary=x", `{"a":"b\u0000c"}`, http.StatusBadRequest},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r, seen := bodyRouter(1 << 20)
			w := post(r, tc.contentType, tc.body, false)
			if w.Code != tc.want {
				t.Fatalf("status %d body %s", w.Code, w.Body.String())
			}
			if tc.want == http.StatusOK && *seen != tc.body {
				t.Fatalf("body was not restored for the handler: %q", *seen)
			}
		})
	}
}

func TestRejectNULBytesExemptsNamedRoutesOnly(t *testing.T) {
	r, seen := bodyRouter(1<<20, "/x")
	body := "--x\r\n\x00\x00"
	if w := post(r, "multipart/form-data; boundary=x", body, false); w.Code != http.StatusOK || *seen != body {
		t.Fatalf("status %d seen %q", w.Code, *seen)
	}
}
