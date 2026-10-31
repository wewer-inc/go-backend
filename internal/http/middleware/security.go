package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/gin-gonic/gin"
)

// SecurityHeaders sets baseline security response headers. HSTS is only emitted
// when the request is served over TLS (directly or via a trusted proxy that set
// X-Forwarded-Proto=https), so it doesn't break plain-HTTP local development.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")

		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}

// BodyLimit caps the size of request bodies to maxBytes, returning 413 when
// exceeded. This prevents a trivial memory-exhaustion DoS from oversized
// payloads reaching json decoding. A declared Content-Length over the cap is
// refused before a byte is read; a body that declares no length is wrapped so
// that reading past the cap fails. A non-positive maxBytes disables the limit.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if maxBytes <= 0 {
			c.Next()
			return
		}
		if c.Request.ContentLength > maxBytes {
			abortWith(c, apierr.PayloadTooLarge(nil))
			return
		}
		if c.Request.Body != nil && c.Request.Body != http.NoBody {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}

// RejectNULBytes answers 400 when a request body contains a NUL character. Postgres text
// columns cannot store one, so without this the write fails as a 500 that points at no
// field, invites a retry that can never work and sets off alerts on the 5xx rate. A single
// filter ahead of every route also stays correct where a check per binder would drift.
//
// The scan covers both forms, because a JSON encoder writes a NUL as a six-character escape
// and such a body holds no zero byte at all. It buffers the whole body, so mount it after
// BodyLimit.
//
// exemptRoutes takes the Gin route templates of binary uploads, whose files contain zero
// bytes as a matter of course. Exemption goes by route and not by Content-Type: clients
// choose that header and JSON binding never consults it, so labelling a JSON body as
// multipart would otherwise be enough to skip the scan.
func RejectNULBytes(exemptRoutes ...string) gin.HandlerFunc {
	exempt := make(map[string]struct{}, len(exemptRoutes))
	for _, r := range exemptRoutes {
		exempt[r] = struct{}{}
	}

	return func(c *gin.Context) {
		_, isExempt := exempt[c.FullPath()]
		if isExempt || !mayCarryText(c.Request) {
			c.Next()
			return
		}

		raw, err := io.ReadAll(c.Request.Body)
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			abortWith(c, apierr.PayloadTooLarge(err))
			return
		}
		if err != nil {
			// An unreadable body is for the handler's bind to report. It sees an empty body
			// and answers as it would for any other invalid request.
			c.Request.Body = io.NopCloser(bytes.NewReader(nil))
			c.Next()
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(raw))

		if holdsNUL(raw) {
			abortWith(c, apierr.BadRequest("invalid_characters", "a text value contains a null character, which cannot be stored"))
			return
		}
		c.Next()
	}
}

func mayCarryText(r *http.Request) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	}
	return false
}

// jsonNULEscapes holds both case spellings of the JSON escape for NUL. They are written out
// byte by byte so that the sequence being searched for never appears in this file.
var jsonNULEscapes = [][]byte{
	{'\\', 'u', '0', '0', '0', '0'},
	{'\\', 'U', '0', '0', '0', '0'},
}

func holdsNUL(raw []byte) bool {
	if bytes.IndexByte(raw, 0) >= 0 {
		return true
	}
	for _, escape := range jsonNULEscapes {
		if bytes.Contains(raw, escape) {
			return true
		}
	}
	return false
}

func abortWith(c *gin.Context, e *apierr.APIError) {
	_ = c.Error(e)
	c.AbortWithStatusJSON(e.Status, apicommon.Response[any]{Error: e.Code, Message: e.Message, Details: e.Details})
}
