package apicommon

import (
	"errors"
	"net/http"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/gin-gonic/gin"
)

// RespondError writes err as the standard error envelope and attaches it to the context,
// where the request logger picks up the cause. The body has only code, message and details.
func RespondError(c *gin.Context, err error) {
	_ = c.Error(err)
	var apiErr *apierr.APIError
	if errors.As(err, &apiErr) {
		c.JSON(apiErr.Status, Response[any]{Error: apiErr.Code, Message: apiErr.Message, Details: apiErr.Details})
		return
	}
	c.JSON(http.StatusInternalServerError, Response[any]{Error: "internal_error"})
}
