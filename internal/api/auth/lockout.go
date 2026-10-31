package auth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/loginfailure"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"gorm.io/gorm"
)

// lockout refuses credential checks for an address after repeated failures. It lives in
// Postgres so it still protects the login route when Redis, and with it the rate limiter,
// is off.
//
// An attempt is reserved before the credential is checked, and given back if it turns out
// to be good. Counting after the check would let parallel guesses all pass the check
// before any of them was counted.
//
// The trade-off is deliberate: a stranger can lock an address out for one window by
// failing on purpose. That costs an inconvenience; no lockout costs the account.
type lockout struct {
	db        *gorm.DB
	threshold int
	window    time.Duration
}

func lockoutKey(email string) string {
	return platformauth.HashToken(strings.ToLower(strings.TrimSpace(email)))
}

func (l *lockout) conn(ctx context.Context) *gorm.DB {
	if tx, ok := store.TxFromContext(ctx); ok {
		return tx.WithContext(ctx)
	}
	return l.db.WithContext(ctx)
}

func (l *lockout) enabled() bool { return l.threshold > 0 }

// reserve takes one attempt for the address. It returns how long the address stays locked
// when the attempt exceeds the threshold, and zero when the attempt may proceed. The
// increment and the count come from one statement, so each of N parallel callers sees a
// different count and no more than the threshold get through.
//
// It also sweeps lapsed rows, since this table grows with whatever addresses are tried.
func (l *lockout) reserve(ctx context.Context, email string) (time.Duration, error) {
	if !l.enabled() {
		return 0, nil
	}
	now := time.Now().UTC()
	key := lockoutKey(email)
	conn := l.conn(ctx)
	if err := conn.Exec(`DELETE FROM login_failures WHERE window_start < ?`, now.Add(-l.window)).Error; err != nil {
		return 0, err
	}
	var count int
	if err := conn.Raw(`
		INSERT INTO login_failures (key_hash, failures, window_start) VALUES (?, 1, ?)
		ON CONFLICT (key_hash) DO UPDATE SET failures = login_failures.failures + 1
		RETURNING failures`, key, now).Scan(&count).Error; err != nil {
		return 0, err
	}
	if count <= l.threshold {
		return 0, nil
	}

	var f loginfailure.Failure
	err := conn.Where("key_hash = ?", key).Take(&f).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return time.Second, nil // cleared a moment ago; still refuse this attempt
	}
	if err != nil {
		return 0, err
	}
	remaining := time.Until(f.WindowStart.Add(l.window))
	if remaining < time.Second {
		remaining = time.Second
	}
	return remaining, nil
}

// release gives back an attempt whose credential turned out to be good. It leaves earlier
// failures counted: knowing a password must not reset the guesses at a second factor.
func (l *lockout) release(ctx context.Context, email string) error {
	if !l.enabled() {
		return nil
	}
	return l.conn(ctx).Exec(`UPDATE login_failures SET failures = failures - 1 WHERE key_hash = ? AND failures > 0`, lockoutKey(email)).Error
}

// clear forgets the address's failures, once it has fully proven who it is.
func (l *lockout) clear(ctx context.Context, email string) error {
	if !l.enabled() {
		return nil
	}
	return l.conn(ctx).Exec(`DELETE FROM login_failures WHERE key_hash = ?`, lockoutKey(email)).Error
}

func lockedError(remaining time.Duration) error {
	minutes := int(math.Ceil(remaining.Minutes()))
	return apierr.TooManyRequests("account_locked", fmt.Sprintf("too many failed attempts; try again in %d minute(s)", minutes))
}

// reserveAttempt is reserve as an API error.
func (s *Service) reserveAttempt(ctx context.Context, email string) error {
	remaining, err := s.lockout.reserve(ctx, email)
	if err != nil {
		return apierr.InternalErr(err, "lockout check failed")
	}
	if remaining > 0 {
		return lockedError(remaining)
	}
	return nil
}

// releaseAttempt gives back a reserved attempt. A failure is logged rather than returned:
// the credential was good, and the cost is one attempt counted too many.
func (s *Service) releaseAttempt(ctx context.Context, email string) {
	if err := s.lockout.release(ctx, email); err != nil {
		s.log.Error().Err(err).Msg("auth: failed to release a login attempt")
	}
}

// clearAttempts forgets the failure count. Logged for the same reason as releaseAttempt.
func (s *Service) clearAttempts(ctx context.Context, email string) {
	if err := s.lockout.clear(ctx, email); err != nil {
		s.log.Error().Err(err).Msg("auth: failed to clear the login failure count")
	}
}
