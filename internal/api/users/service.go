// Package users manages accounts from the admin side.
package users

import (
	"context"
	"errors"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/authz"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/sessions"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Service handles account management.
type Service struct {
	db    *gorm.DB
	users repo.Repo[user.User]
	audit *auditlog.Recorder
}

// NewService returns a Service that reads users from db and audits through recorder.
func NewService(db *gorm.DB, recorder *auditlog.Recorder) *Service {
	return &Service{db: db, users: repo.NewGormRepo[user.User](db), audit: recorder}
}

// refusal is a role change turned down inside the transaction. The denied audit row is
// written after the rollback, because written inside it would be rolled back too.
type refusal struct {
	err    error
	reason string
}

func (r *refusal) Error() string { return r.reason }

// ChangeRole changes a user's role and signs them out everywhere.
//
// Every row the decision rests on is locked in one ordered statement: all admins, the
// actor and the target. Two admins demoting each other would otherwise each count two
// admins, both proceed, and leave none. Taking the locks together and by id means they
// cannot deadlock either. The actor's role is read again under that lock, so an actor
// demoted a moment ago cannot use the role their request started with.
func (s *Service) ChangeRole(ctx context.Context, actor authz.Subject, targetUUID, requested, ip string) (*RoleResponse, error) {
	newRole := entities.Role(requested)
	if !newRole.Valid() {
		return nil, apierr.InvalidField("role", "unknown role")
	}
	id, err := uuid.Parse(targetUUID)
	if err != nil {
		return nil, apierr.NotFound("user_not_found", "user not found")
	}

	var target *user.User
	var oldRole entities.Role
	var changed bool
	err = store.WithTx(ctx, s.db, func(ctx context.Context, tx *gorm.DB) error {
		var rows []user.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("platform_role = ? OR id = ? OR uuid = ?", entities.RoleAdmin, actor.UserID, id).
			Order("id").Find(&rows).Error; err != nil {
			return apierr.InternalErr(err, "failed to read users")
		}

		admins := 0
		var actorRow *user.User
		for i := range rows {
			if rows[i].PlatformRole == entities.RoleAdmin {
				admins++
			}
			if rows[i].ID == actor.UserID {
				actorRow = &rows[i]
			}
			if rows[i].UUID == id {
				target = &rows[i]
			}
		}
		if target == nil {
			return apierr.NotFound("user_not_found", "user not found")
		}
		oldRole = target.PlatformRole

		forbidden := apierr.Forbidden("insufficient permissions")
		if actorRow == nil || !authz.HasCapability(actorRow.PlatformRole, authz.CapUsersRoleUpdate) {
			return &refusal{err: forbidden, reason: "actor_lacks_capability"}
		}
		if !authz.CanAssignRole(actorRow.PlatformRole, newRole) {
			return &refusal{err: forbidden, reason: "cannot_assign_role"}
		}
		if !authz.CanChangeRoleFrom(actorRow.PlatformRole, oldRole) {
			return &refusal{err: forbidden, reason: "cannot_change_role_from"}
		}
		if oldRole == newRole {
			return nil
		}
		if oldRole == entities.RoleAdmin && admins <= 1 {
			return &refusal{
				err:    apierr.Conflict("last_admin", "the last admin cannot be demoted"),
				reason: "last_admin",
			}
		}

		updated, err := s.users.UpdateColumnsGuarded(ctx, target.ID,
			map[string]any{"platform_role": oldRole}, nil, map[string]any{"platform_role": newRole})
		if err != nil {
			return apierr.InternalErr(err, "failed to update role")
		}
		if !updated {
			return apierr.Internal("failed to update role")
		}
		// Authorization already reads the role fresh on each request. Revoking makes the
		// change unmistakable to the user, and also ends any login-as session they started.
		if _, err := sessions.RevokeAll(ctx, s.db, target.ID, uuid.Nil); err != nil {
			return apierr.InternalErr(err, "failed to revoke sessions")
		}
		// Required: a role change with no record of it must not stand.
		if s.audit != nil {
			if err := s.audit.Record(ctx, auditlog.Entry{
				Event:       audit.EventUserRoleChanged,
				ActorUserID: &actor.UserID,
				IP:          ip,
				Detail: map[string]any{
					"target_user_uuid": target.UUID.String(),
					"old_role":         string(oldRole),
					"new_role":         string(newRole),
				},
			}); err != nil {
				return apierr.InternalErr(err, "failed to record audit event")
			}
		}
		changed = true
		return nil
	})

	var refused *refusal
	if errors.As(err, &refused) {
		s.recordDenied(ctx, actor, id, oldRole, newRole, refused.reason, ip)
		return nil, refused.err
	}
	if err != nil {
		return nil, err
	}

	current := newRole
	if !changed {
		current = oldRole
	}
	return &RoleResponse{UUID: target.UUID.String(), PlatformRole: string(current)}, nil
}

// recordDenied audits a turned-down role change, the kind of anomaly an operator goes to the
// trail to find. A write failure is ignored here: the recorder has logged it, and the
// request is being refused either way.
func (s *Service) recordDenied(ctx context.Context, actor authz.Subject, target uuid.UUID, oldRole, requested entities.Role, reason, ip string) {
	if s.audit == nil {
		return
	}
	_ = s.audit.Record(ctx, auditlog.Entry{
		Event:       audit.EventUserRoleChangeDenied,
		ActorUserID: &actor.UserID,
		IP:          ip,
		Detail: map[string]any{
			"target_user_uuid": target.String(),
			"old_role":         string(oldRole),
			"requested_role":   string(requested),
			"reason":           reason,
		},
	})
}
