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

// lockout refuses sign-ins for an address after repeated failures. It lives in Postgres
// so it still protects the login route when Redis, and with it the rate limiter, is off.
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

// retryAfter returns how long the address stays locked, zero when it is not.
func (l *lockout) retryAfter(ctx context.Context, email string) (time.Duration, error) {
	if !l.enabled() {
		return 0, nil
	}
	var f loginfailure.Failure
	err := l.conn(ctx).Where("key_hash = ?", lockoutKey(email)).Take(&f).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	remaining := time.Until(f.WindowStart.Add(l.window))
	if f.Failures < l.threshold || remaining <= 0 {
		return 0, nil
	}
	return remaining, nil
}

// fail counts a failure atomically, starting a new window if the last one has lapsed. It
// also sweeps lapsed rows, since this table grows with whatever addresses are tried.
func (l *lockout) fail(ctx context.Context, email string) error {
	if !l.enabled() {
		return nil
	}
	now := time.Now().UTC()
	cutoff := now.Add(-l.window)
	conn := l.conn(ctx)
	if err := conn.Exec(`DELETE FROM login_failures WHERE window_start < ?`, cutoff).Error; err != nil {
		return err
	}
	return conn.Exec(`
		INSERT INTO login_failures (key_hash, failures, window_start) VALUES (?, 1, ?)
		ON CONFLICT (key_hash) DO UPDATE SET failures = login_failures.failures + 1`,
		lockoutKey(email), now,
	).Error
}

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
