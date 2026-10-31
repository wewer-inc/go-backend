package middleware

import (
	"net/http"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const ctxActorSubject = "actor_subject"

// authzDeniedTotal counts route-level denials. Every label comes from a closed set;
// adding a user id or a path would let the number of series grow without limit.
var authzDeniedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "authz_denied_total",
	Help: "Route-level authorization denials by permission, role and reason.",
}, []string{"permission", "role", "reason"})

// GetActorSubject returns the subject UserAuth built from the database row. Any decision
// that depends on who is acting must read this and leave the token's claims alone.
func GetActorSubject(c *gin.Context) (authz.Subject, bool) {
	v, ok := c.Get(ctxActorSubject)
	s, ok2 := v.(authz.Subject)
	return s, ok && ok2
}

// RequirePermission rejects a request whose role lacks the action on the resource. It
// needs UserAuth in front of it.
//
// It speaks for the role as a whole, before any row is known. Code that reaches a
// particular row still calls authz.Decide, and list queries still use scopequery.
func RequirePermission(res authz.Resource, action authz.Action) gin.HandlerFunc {
	perm := string(authz.Perm(res, action))
	return func(c *gin.Context) {
		s, ok := GetActorSubject(c)
		if !ok {
			// No subject means UserAuth is missing from the chain. Letting the request
			// through would make a broken gate look healthy, so it is rejected.
			unauthorized(c, "unauthorized")
			return
		}
		if !authz.Can(s.Role, res, action) {
			deny(c, perm, s, authz.ReasonNoGrant)
			return
		}
		c.Next()
	}
}

// RequireCapability gates a route on a capability, including its impersonation bar.
func RequireCapability(capability authz.Capability) gin.HandlerFunc {
	return func(c *gin.Context) {
		s, ok := GetActorSubject(c)
		if !ok {
			unauthorized(c, "unauthorized")
			return
		}
		if d := authz.DecideCapability(s, capability); !d.Allowed {
			deny(c, string(capability), s, d.Reason)
			return
		}
		c.Next()
	}
}

// RefuseImpersonated rejects a request made from a "login as" session. It belongs on the
// routes that alter an account's own credentials or sessions, since impersonation exists
// for viewing an account and not for changing its password or ending its sessions. Every
// user may call those routes on themselves, so no capability covers them and the
// capability bar cannot help.
func RefuseImpersonated() gin.HandlerFunc {
	return func(c *gin.Context) {
		s, ok := GetActorSubject(c)
		if !ok {
			unauthorized(c, "unauthorized")
			return
		}
		if s.Impersonator != nil {
			deny(c, "account_security", s, authz.ReasonImpersonation)
			return
		}
		c.Next()
	}
}

func deny(c *gin.Context, permission string, s authz.Subject, reason authz.DenyReason) {
	authzDeniedTotal.WithLabelValues(permission, string(s.Role), string(reason)).Inc()
	e := apierr.Forbidden("insufficient permissions")
	_ = c.Error(e)
	c.AbortWithStatusJSON(http.StatusForbidden, apicommon.Response[any]{Error: e.Code, Message: e.Message})
}

// SetActorForTest puts a subject on the context the way UserAuth does, for tests of
// the modules behind it. Production code never calls it: only UserAuth sets the actor.
func SetActorForTest(c *gin.Context, s authz.Subject) {
	c.Set(ctxActorUserID, s.UserID)
	c.Set(ctxActorPlatformRole, s.Role)
	c.Set(ctxActorSubject, s)
}
