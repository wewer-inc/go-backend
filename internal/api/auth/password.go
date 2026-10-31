package auth

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/url"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/passwordhistory"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/passwordreset"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/sessions"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/worker"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// jobTimeout bounds a background job, which otherwise has only the app's context.
const jobTimeout = 30 * time.Second

func weakPasswordError(pw string) error {
	return apierr.BadRequest("weak_password", platformauth.ErrWeakPassword.Error()).
		WithDetails(map[string]any{"requirements": platformauth.PasswordProblems(pw)})
}

// checkNewPassword applies the policy and the reuse rule, and returns the new hash. It
// runs before any transaction opens, because bcrypt is slow on purpose.
func (s *Service) checkNewPassword(ctx context.Context, u *user.User, pw string) (string, error) {
	if platformauth.ValidatePassword(pw) != nil {
		return "", weakPasswordError(pw)
	}
	reused, err := s.passwordWasUsed(ctx, u, pw)
	if err != nil {
		return "", err
	}
	if reused {
		return "", apierr.BadRequest("password_reused", "you cannot reuse a recent password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", apierr.InternalErr(err, "failed to hash password")
	}
	return string(hash), nil
}

// passwordWasUsed checks the current password and the last historyCount. With history
// disabled, the current password is still refused.
func (s *Service) passwordWasUsed(ctx context.Context, u *user.User, pw string) (bool, error) {
	if u.PasswordHash != "" && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pw)) == nil {
		return true, nil
	}
	if s.historyCount <= 0 {
		return false, nil
	}
	entries, _, err := s.historyRepo.List(ctx, store.QueryOpts{
		Filters:  map[string]any{"user_id": u.ID},
		Sort:     []store.SortField{{Field: "id", Desc: true}},
		PageSize: s.historyCount,
	})
	if err != nil {
		return false, apierr.InternalErr(err, "failed to check password history")
	}
	for i := range entries {
		if bcrypt.CompareHashAndPassword([]byte(entries[i].PasswordHash), []byte(pw)) == nil {
			return true, nil
		}
	}
	return false, nil
}

// storeNewPassword writes the hash and moves the old one into history. Call it inside a
// transaction, so a password never changes without the sessions and audit row around it.
func (s *Service) storeNewPassword(ctx context.Context, u *user.User, newHash string) error {
	if err := s.userRepo.UpdateColumnsByID(ctx, u.ID, map[string]any{"password_hash": newHash}); err != nil {
		return apierr.InternalErr(err, "failed to update password")
	}
	if u.PasswordHash == "" || s.historyCount <= 0 {
		return nil
	}
	if err := s.historyRepo.Create(ctx, &passwordhistory.Entry{UserID: u.ID, PasswordHash: u.PasswordHash}); err != nil {
		return apierr.InternalErr(err, "failed to record password history")
	}
	// Fetching one more than is kept finds what to drop. Changes happen one at a time, so
	// no more than that can be over the limit.
	entries, _, err := s.historyRepo.List(ctx, store.QueryOpts{
		Filters:  map[string]any{"user_id": u.ID},
		Sort:     []store.SortField{{Field: "id", Desc: true}},
		PageSize: s.historyCount + 1,
	})
	if err != nil {
		return apierr.InternalErr(err, "failed to trim password history")
	}
	for i := s.historyCount; i < len(entries); i++ {
		if err := s.historyRepo.HardDelete(ctx, entries[i].ID); err != nil {
			return apierr.InternalErr(err, "failed to trim password history")
		}
	}
	return nil
}

// ChangePassword checks the current password, stores the new one and ends every session
// except the one making the request.
func (s *Service) ChangePassword(ctx context.Context, userID uint, currentSID string, req ChangePasswordRequest, ip string) error {
	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return apierr.InternalErr(err, "user lookup failed")
	}
	if u.PasswordHash == "" {
		return apierr.BadRequest("oauth_only", "this account uses Google sign-in")
	}
	keep, err := uuid.Parse(currentSID)
	if err != nil {
		return apierr.Unauthorized("invalid session")
	}

	// Guessing the current password through a stolen access token counts like guessing it
	// at the login form.
	remaining, err := s.lockout.retryAfter(ctx, u.Email)
	if err != nil {
		return apierr.InternalErr(err, "lockout check failed")
	}
	if remaining > 0 {
		return lockedError(remaining)
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.CurrentPassword)) != nil {
		s.countFailure(ctx, u.Email)
		// A 400, not a 401: the session is fine, and clients treat a 401 as signed out.
		return apierr.BadRequest("current_password_incorrect", "current password is incorrect")
	}

	newHash, err := s.checkNewPassword(ctx, u, req.NewPassword)
	if err != nil {
		return err
	}

	err = store.WithTx(ctx, s.db, func(ctx context.Context, _ *gorm.DB) error {
		if err := s.storeNewPassword(ctx, u, newHash); err != nil {
			return err
		}
		if _, err := sessions.RevokeAll(ctx, s.db, u.ID, keep); err != nil {
			return apierr.InternalErr(err, "failed to revoke sessions")
		}
		return s.recordRequired(ctx, auditlog.Entry{Event: audit.EventPasswordChanged, ActorUserID: &u.ID, IP: ip})
	})
	if err != nil {
		return err
	}
	s.mailPasswordChanged(u)
	return nil
}

// RequestPasswordReset starts forgot-password. It does everything on the worker, and the
// lookup itself is part of that: run inline, the time it takes would reveal whether the
// address has an account, however identical the response. The caller gets nothing back
// to base a different answer on, and a full queue changes nothing the client can see.
func (s *Service) RequestPasswordReset(email string, lc LoginContext) {
	err := s.jobs.Enqueue(func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, jobTimeout)
		defer cancel()
		return s.issueReset(ctx, email, lc)
	})
	if err != nil {
		s.log.Warn().Err(err).Msg("auth: password reset request dropped")
	}
}

// issueReset mints a token and emails it. Every way of not sending is silent, and none
// touches the password or the sessions, so a request nobody made costs the account nothing.
func (s *Service) issueReset(ctx context.Context, email string, lc LoginContext) error {
	if s.resetURL == "" {
		s.log.Error().Msg("auth: PASSWORD_RESET_URL is not set; password reset emails cannot be sent")
		return nil
	}
	u, err := s.userRepo.GetOne(ctx, store.QueryOpts{Filters: map[string]any{"email": email}})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("password reset lookup: %w", err)
	}
	if u.PasswordHash == "" {
		return nil // signs in with Google; there is no password to reset
	}

	// Rate limiting counts per client, so a sender moving between addresses gets past it.
	// This per-user cooldown is what keeps a target's inbox from being flooded that way.
	if s.resetCooldown > 0 {
		recent, err := s.resetRepo.Exists(ctx, store.QueryOpts{
			Filters: map[string]any{"user_id": u.ID},
			Where:   []store.Clause{{Expr: "created_at > ?", Args: []any{time.Now().UTC().Add(-s.resetCooldown)}}},
		})
		if err != nil {
			return fmt.Errorf("password reset cooldown: %w", err)
		}
		if recent {
			return nil
		}
	}

	raw, err := platformauth.GenerateOpaqueToken()
	if err != nil {
		return fmt.Errorf("password reset token: %w", err)
	}
	link, err := resetLink(s.resetURL, raw)
	if err != nil {
		return fmt.Errorf("password reset url: %w", err)
	}

	err = store.WithTx(ctx, s.db, func(ctx context.Context, tx *gorm.DB) error {
		// Only the newest link works.
		if err := tx.Model(&passwordreset.Token{}).
			Where("user_id = ? AND consumed_at IS NULL", u.ID).
			Update("consumed_at", time.Now().UTC()).Error; err != nil {
			return err
		}
		now := time.Now().UTC()
		return s.resetRepo.Create(ctx, &passwordreset.Token{
			Model:     gorm.Model{CreatedAt: now},
			UserID:    u.ID,
			TokenHash: platformauth.HashToken(raw),
			ExpiresAt: now.Add(s.resetTTL),
			RequestIP: lc.IP,
		})
	})
	if err != nil {
		return fmt.Errorf("password reset token: %w", err)
	}

	// Nil actor: whoever asked did not prove they are this user.
	s.record(ctx, audit.EventPasswordResetRequested, nil, lc.IP, map[string]any{"target_user_uuid": u.UUID.String()})

	body := fmt.Sprintf(`<p>Someone asked to reset the password for this account.</p>`+
		`<p><a href="%s">Choose a new password</a>. This link works once and expires in %d minutes.</p>`+
		`<p>If this was not you, ignore this email. Your password has not changed.</p>`,
		html.EscapeString(link), int(s.resetTTL.Minutes()))
	if err := s.mailer.Send(ctx, u.Email, "Reset your password", body); err != nil {
		return fmt.Errorf("password reset email: %w", err)
	}
	return nil
}

func resetLink(base, token string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ResetPassword finishes the forgot-password flow. Given a live token it stores the new
// password, marks the token spent and revokes all of the user's sessions, because someone
// locked out of an account may have lost it to an attacker. No session is created here, so
// a second factor or any other protection still applies at the next sign-in.
func (s *Service) ResetPassword(ctx context.Context, req ResetPasswordRequest, lc LoginContext) error {
	hash := platformauth.HashToken(req.Token)
	tok, err := s.resetRepo.GetOne(ctx, store.QueryOpts{Filters: map[string]any{"token_hash": hash}})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return apierr.BadRequest("invalid_token", "this reset link is invalid")
	}
	if err != nil {
		return apierr.InternalErr(err, "reset token lookup failed")
	}
	if tok.ConsumedAt != nil {
		return apierr.Conflict("token_used", "this reset link has already been used")
	}
	if time.Now().After(tok.ExpiresAt) {
		return apierr.BadRequest("token_expired", "this reset link has expired; request a new one")
	}

	u, err := s.userRepo.GetByID(ctx, tok.UserID)
	if err != nil {
		return apierr.InternalErr(err, "user lookup failed")
	}
	// A refused password leaves the token usable, so a weak first try costs a retry rather
	// than a new email.
	newHash, err := s.checkNewPassword(ctx, u, req.NewPassword)
	if err != nil {
		return err
	}

	err = store.WithTx(ctx, s.db, func(ctx context.Context, _ *gorm.DB) error {
		// The compare-and-set is what makes the token single-use: of two concurrent
		// redemptions, only one matches a row.
		claimed, err := s.resetRepo.UpdateColumnsGuarded(ctx, tok.ID,
			map[string]any{"consumed_at": nil},
			[]store.Clause{{Expr: "expires_at > ?", Args: []any{time.Now().UTC()}}},
			map[string]any{"consumed_at": time.Now().UTC()})
		if err != nil {
			return apierr.InternalErr(err, "failed to redeem reset token")
		}
		if !claimed {
			return apierr.Conflict("token_used", "this reset link has already been used")
		}
		if err := s.storeNewPassword(ctx, u, newHash); err != nil {
			return err
		}
		if _, err := sessions.RevokeAll(ctx, s.db, u.ID, uuid.Nil); err != nil {
			return apierr.InternalErr(err, "failed to revoke sessions")
		}
		if err := s.lockout.clear(ctx, u.Email); err != nil {
			return apierr.InternalErr(err, "failed to clear lockout")
		}
		return s.recordRequired(ctx, auditlog.Entry{Event: audit.EventPasswordReset, ActorUserID: &u.ID, IP: lc.IP})
	})
	if err != nil {
		return err
	}
	s.mailPasswordChanged(u)
	return nil
}

// mailPasswordChanged tells the user, so a change they did not make gets noticed. Sent
// from the worker: a slow mail server must not hold up the request, and a failed send
// must not undo a password change that already committed.
func (s *Service) mailPasswordChanged(u *user.User) {
	s.enqueue(func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, jobTimeout)
		defer cancel()
		return s.mailer.Send(ctx, u.Email, "Your password was changed",
			`<p>The password for this account was just changed, and other devices were signed out.</p>`+
				`<p>If this was not you, reset your password now.</p>`)
	})
}

func (s *Service) enqueue(job worker.Job) {
	if err := s.jobs.Enqueue(job); err != nil {
		s.log.Warn().Err(err).Msg("auth: background job dropped")
	}
}

// countFailure records a failed credential check. A write failure is logged rather than
// returned: the caller is already answering with a refusal.
func (s *Service) countFailure(ctx context.Context, email string) {
	if err := s.lockout.fail(ctx, email); err != nil {
		s.log.Error().Err(err).Msg("auth: failed to count a login failure")
	}
}
