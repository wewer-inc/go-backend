package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	apicommon "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/api/common"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/http/middleware"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ImpersonationTTL caps an impersonated session at five minutes, which is enough to look
// at a reported problem. Nothing renews it, so an admin who walks away simply loses access.
const ImpersonationTTL = 5 * time.Minute

// StartImpersonation lets an admin act as another user for ImpersonationTTL. Route
// middleware has checked the capability and turned away nested sessions by this point, so
// only the rules that need the target row remain. The target cannot be the actor, and it
// cannot be another admin: taking over a peer's account teaches nothing about a user's
// problem and only widens the actor's reach.
//
// The session never holds a redeemable refresh token, which makes the TTL final.
func (s *Service) StartImpersonation(ctx context.Context, actor authz.Subject, targetUUID string, lc LoginContext) (*ImpersonateResponse, error) {
	id, err := uuid.Parse(targetUUID)
	if err != nil {
		return nil, apierr.NotFound("user_not_found", "user not found")
	}
	target, err := s.userRepo.GetByUUID(ctx, id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, apierr.NotFound("user_not_found", "user not found")
	}
	if err != nil {
		return nil, apierr.InternalErr(err, "user lookup failed")
	}

	if target.ID == actor.UserID {
		s.recordImpersonationDenied(ctx, actor, target, "self", lc.IP)
		return nil, apierr.BadRequest("self_action", "you cannot impersonate yourself")
	}
	if target.PlatformRole == entities.RoleAdmin {
		s.recordImpersonationDenied(ctx, actor, target, "target_is_admin", lc.IP)
		return nil, apierr.ForbiddenCode("not_impersonatable", "this user cannot be impersonated")
	}

	// A random hash nobody holds the preimage of. An empty one could be matched by a
	// request presenting an empty token, turning this into a renewable session.
	unusable, err := platformauth.GenerateOpaqueToken()
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to create impersonation session")
	}

	now := time.Now().UTC()
	expires := now.Add(ImpersonationTTL)
	impersonator := actor.UserID
	sess := &session.Session{
		UUID:               uuid.New(),
		UserID:             target.ID,
		RefreshTokenHash:   platformauth.HashToken(unusable),
		LoginMethod:        session.MethodImpersonation,
		ImpersonatorUserID: &impersonator,
		UserAgent:          lc.UserAgent,
		IP:                 lc.IP,
		LastUsedAt:         now,
		ExpiresAt:          expires,
		AbsoluteExpiry:     expires,
	}

	var access platformauth.IssuedToken
	err = store.WithTx(ctx, s.db, func(ctx context.Context, _ *gorm.DB) error {
		if err := s.sessionRepo.Create(ctx, sess); err != nil {
			return apierr.InternalErr(err, "failed to create impersonation session")
		}
		var err error
		access, err = s.issuer.IssueAccessToken(platformauth.AccessParams{
			Subject:      target.UUID.String(),
			SID:          sess.UUID.String(),
			Impersonator: impersonator,
			TTL:          ImpersonationTTL,
		})
		if err != nil {
			return apierr.InternalErr(err, "failed to issue impersonation token")
		}
		// Required: a login-as session with no record of it must not exist. Explicit, since
		// this runs on the admin's own ordinary session and the context names nobody.
		return s.recordRequired(ctx, auditlog.Entry{
			Event:              audit.EventImpersonationStarted,
			ActorUserID:        &actor.UserID,
			ImpersonatorUserID: &impersonator,
			IP:                 lc.IP,
			Detail: map[string]any{
				"target_user_uuid": target.UUID.String(),
				"session":          sess.UUID.String(),
				"expires_at":       expires.Format(time.RFC3339),
			},
		})
	})
	if err != nil {
		return nil, err
	}

	return &ImpersonateResponse{
		AccessToken: access.Token,
		ExpiresAt:   access.ExpiresAt,
		SessionUUID: sess.UUID.String(),
		Target:      authResponse(target, "", "").User,
	}, nil
}

// EndImpersonation closes the impersonated session making the request and audits it. A
// normal session gets a 400 here, because ending one is the job of logout, and a client
// bug should not be able to sign a real user out through this endpoint.
func (s *Service) EndImpersonation(ctx context.Context, subject authz.Subject, sid, ip string) error {
	if subject.Impersonator == nil {
		return apierr.BadRequest("not_impersonating", "this is not an impersonation session")
	}
	sess, err := s.sessionByUUID(ctx, sid)
	if err != nil {
		return apierr.InternalErr(err, "session lookup failed")
	}
	if err := s.revokeSession(ctx, sess); err != nil {
		return err
	}
	return s.recordRequired(ctx, auditlog.Entry{
		Event:              audit.EventImpersonationEnded,
		ActorUserID:        &subject.UserID,
		ImpersonatorUserID: subject.Impersonator,
		IP:                 ip,
		Detail:             map[string]any{"session": sess.UUID.String()},
	})
}

// recordImpersonationDenied chains a refused attempt, which is an access anomaly rather
// than a routine 403. No impersonator on the row: no session was opened.
func (s *Service) recordImpersonationDenied(ctx context.Context, actor authz.Subject, target *user.User, reason, ip string) {
	s.record(ctx, audit.EventImpersonationDenied, &actor.UserID, ip, map[string]any{
		"target_user_uuid": target.UUID.String(),
		"reason":           reason,
	})
}

// StartImpersonation handles a request to act as the user in the uuid path parameter.
func (h *Handler) StartImpersonation(c *gin.Context) {
	s, ok := middleware.GetActorSubject(c)
	if !ok {
		respondError(c, apierr.Unauthorized("unauthorized"))
		return
	}
	// The capability is barred inside impersonation already. Nesting is the one path that
	// could feed itself, so it gets this second check should the barred list ever change.
	if s.Impersonator != nil {
		respondError(c, apierr.ForbiddenCode("already_impersonating", "you cannot impersonate from an impersonation session"))
		return
	}
	resp, err := h.svc.StartImpersonation(c.Request.Context(), s, c.Param("uuid"), loginContext(c))
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, apicommon.Response[ImpersonateResponse]{Data: resp})
}

// EndImpersonation handles a request to leave the current impersonated session.
func (h *Handler) EndImpersonation(c *gin.Context) {
	s, ok := middleware.GetActorSubject(c)
	if !ok {
		respondError(c, apierr.Unauthorized("unauthorized"))
		return
	}
	claims, _ := middleware.GetActorClaims(c)
	if err := h.svc.EndImpersonation(c.Request.Context(), s, claims.SID, c.ClientIP()); err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, apicommon.Response[any]{Message: "impersonation ended"})
}
