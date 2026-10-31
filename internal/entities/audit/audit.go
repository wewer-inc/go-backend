// Package audit holds the security audit record and the names of the events written
// to it.
package audit

import "time"

// Event names. Add to this list rather than inventing a string at the call site, so
// the set of events an operator can filter on stays knowable.
const (
	EventLoginSuccess = "login.success"
	EventLoginFailure = "login.failure"
	EventLoginLocked  = "login.locked"
	EventLogout       = "auth.logout"

	EventTokenRefresh = "token.refresh"
	EventRefreshReuse = "token.refresh_reuse_detected"
	// EventRefreshRace marks a refresh beaten by a concurrent one. It does no harm, but
	// watching its rate shows when the race window has grown too tight for real clients.
	EventRefreshRace = "token.refresh_race"

	EventSessionRevoked = "session.revoked"

	EventPasswordChanged        = "auth.password_changed"
	EventPasswordResetRequested = "auth.password_reset_requested"
	EventPasswordReset          = "auth.password_reset"

	EventMFAEnrolled = "mfa.enrolled"
	EventMFAReset    = "mfa.reset"

	EventMFAFailed   = "mfa.failed"
	EventMFAVerified = "mfa.verified"

	EventMFABackupUsed        = "mfa.backup_code_used"
	EventMFABackupRegenerated = "mfa.backup_codes_regenerated"

	EventImpersonationStarted = "impersonation.started"
	EventImpersonationEnded   = "impersonation.ended"
	// EventImpersonationDenied is written although no session opened: an attempt on a peer's
	// account is worth investigating in a way that an ordinary 403 is not.
	EventImpersonationDenied = "impersonation.denied"

	EventUserRoleChanged = "user.role_changed"
	// EventUserRoleChangeDenied is written when a role change is turned down.
	EventUserRoleChangeDenied = "user.role_change_denied"
)

// Log is one link in the hash chain. Rows are only ever inserted. An update path or a soft
// delete would leave changes that a verifier could not tell from an attack.
type Log struct {
	ID        uint      `gorm:"primaryKey"               json:"id"`
	CreatedAt time.Time `gorm:"index;not null"           json:"created_at"`
	Event     string    `gorm:"type:text;not null;index" json:"event"`
	// ActorUserID is who the request authenticated as, or the account a failed sign-in
	// named; nil when neither is known.
	ActorUserID *uint `gorm:"index" json:"actor_user_id,omitempty"`
	// ImpersonatorUserID names the admin behind a "login as" session on each row that
	// session writes, which keeps the impersonated user from looking solely responsible.
	ImpersonatorUserID *uint  `gorm:"index"     json:"impersonator_user_id,omitempty"`
	IP                 string `gorm:"type:text" json:"ip,omitempty"`
	// Detail is JSON held as text, not jsonb: jsonb normalizes key order and whitespace,
	// which would change the bytes the hash covers.
	Detail string `gorm:"type:text" json:"detail,omitempty"`
	// ChainVersion names the field set Hash covers, so adding a hashed field later leaves
	// existing rows verifiable.
	ChainVersion int    `gorm:"not null;default:1" json:"chain_version"`
	PrevHash     string `gorm:"type:text"          json:"prev_hash"`
	Hash         string `gorm:"type:text;not null" json:"hash"`
}

func (Log) TableName() string { return "audit_logs" }
