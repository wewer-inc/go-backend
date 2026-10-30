package apicommon

import (
	"errors"
	"net/http"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/gin-gonic/gin"
)

// RespondBindError writes the response for a body that could not be bound: a 400
// invalid_request_body with a fixed message. The decoding error is attached for the
// request log only, since its wording is about Go ("json: cannot unmarshal string into
// Go struct field ...") and mentions fields that clients never see.
//
// When the body was cut off by the size cap, the problem is its length rather than its
// format, so the response is 413 payload_too_large instead.
func RespondBindError(c *gin.Context, err error) {
	var tooBig *http.MaxBytesError
	e := apierr.InvalidRequestBody(err)
	if errors.As(err, &tooBig) {
		e = apierr.PayloadTooLarge(err)
	}
	_ = c.Error(e)
	c.JSON(e.Status, Response[any]{Error: e.Code, Message: e.Message, Details: e.Details})
}
