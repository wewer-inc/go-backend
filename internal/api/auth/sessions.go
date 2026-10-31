package auth

import (
	"context"
	"errors"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/sessions"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

func (s *Service) sessionByUUID(ctx context.Context, sid string) (*session.Session, error) {
	id, err := uuid.Parse(sid)
	if err != nil {
		return nil, gorm.ErrRecordNotFound
	}
	return s.sessionRepo.GetOne(ctx, store.QueryOpts{Filters: map[string]any{"uuid": id}})
}

// revokeSession marks one session revoked. Guarded so a second revocation does not move
// the original timestamp.
func (s *Service) revokeSession(ctx context.Context, sess *session.Session) error {
	if sess.RevokedAt != nil {
		return nil
	}
	if _, err := s.sessionRepo.UpdateColumnsGuarded(ctx, sess.ID,
		map[string]any{"revoked_at": nil}, nil, map[string]any{"revoked_at": time.Now().UTC()},
	); err != nil {
		return apierr.InternalErr(err, "failed to revoke session")
	}
	return nil
}

// ListSessions returns up to 100 of the user's unrevoked, unexpired sessions, ordered by
// last use with the latest first.
func (s *Service) ListSessions(ctx context.Context, userID uint, currentSID string) ([]SessionView, error) {
	query := store.QueryOpts{
		Filters:  map[string]any{"user_id": userID},
		Sort:     []store.SortField{{Field: "last_used_at", Desc: true}},
		PageSize: 100,
		Where: []store.Clause{
			{Expr: "absolute_expiry > ?", Args: []any{time.Now().UTC()}},
			{Expr: "revoked_at IS NULL"},
		},
	}
	rows, _, err := s.sessionRepo.List(ctx, query)
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to list sessions")
	}
	views := make([]SessionView, len(rows))
	for i := range rows {
		views[i] = toSessionView(&rows[i], currentSID)
	}
	return views, nil
}

// RevokeSession ends one session of the user's, which may be the one they are using. A
// session owned by someone else gets the same 404 as an unknown id, hiding that it exists.
func (s *Service) RevokeSession(ctx context.Context, userID uint, targetSID, ip string) error {
	sess, err := s.sessionByUUID(ctx, targetSID)
	if errors.Is(err, gorm.ErrRecordNotFound) || (err == nil && sess.UserID != userID) {
		return apierr.NotFound("session_not_found", "session not found")
	}
	if err != nil {
		return apierr.InternalErr(err, "session lookup failed")
	}
	if err := s.revokeSession(ctx, sess); err != nil {
		return err
	}
	s.record(ctx, audit.EventSessionRevoked, &userID, ip, map[string]any{"session": sess.UUID.String(), "scope": "one"})
	return nil
}

// RevokeOtherSessions signs the user out everywhere but the current session.
func (s *Service) RevokeOtherSessions(ctx context.Context, userID uint, currentSID, ip string) error {
	keep, err := uuid.Parse(currentSID)
	if err != nil {
		return apierr.Unauthorized("invalid session")
	}
	n, err := sessions.RevokeAll(ctx, s.db, userID, keep)
	if err != nil {
		return apierr.InternalErr(err, "failed to revoke sessions")
	}
	s.record(ctx, audit.EventSessionRevoked, &userID, ip, map[string]any{"scope": "others", "count": n})
	return nil
}
