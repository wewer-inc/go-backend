package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"image/png"
	"strings"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/apierr"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/mfa"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/user"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auditlog"
	platformauth "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/auth"
	appcrypto "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/crypto"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/sessions"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
)

// statusMFARequired is the status on a challenge response.
const statusMFARequired = "mfa_required"

// backupCodeBytes is 80 bits. Backup codes are hashed with fast SHA-256, so they need
// enough entropy that a leaked table cannot be brute forced.
const backupCodeBytes = 10

var errInvalidCode = errors.New("auth: invalid mfa code")

func (s *Service) mfaAvailable() error {
	if s.mfaKey == nil {
		return apierr.ServiceUnavailable("mfa_unavailable", "two-factor authentication is not configured on this server")
	}
	return nil
}

// totpValid checks a code against the user's stored secret. An undecryptable secret is
// logged and reads as a wrong code: backup codes still work, and the account is not locked
// out of them by a rotated key.
func (s *Service) totpValid(u *user.User, code string) bool {
	if u.TOTPSecretEnc == "" || s.mfaKey == nil {
		return false
	}
	secret, err := appcrypto.Decrypt(s.mfaKey, u.TOTPSecretEnc)
	if err != nil {
		s.log.Error().Err(err).Uint("user_id", u.ID).Msg("auth: could not decrypt a totp secret")
		return false
	}
	return totp.Validate(code, secret)
}

// startChallenge creates the challenge an enrolled user must pass to get a session.
func (s *Service) startChallenge(ctx context.Context, u *user.User, method session.LoginMethod) (*MFAChallengeResponse, error) {
	raw, err := platformauth.GenerateOpaqueToken()
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to start mfa")
	}
	expires := time.Now().UTC().Add(s.challengeTTL)
	if err := s.challengeRepo.Create(ctx, &mfa.Challenge{
		UserID:    u.ID,
		TokenHash: platformauth.HashToken(raw),
		Method:    method,
		ExpiresAt: expires,
	}); err != nil {
		return nil, apierr.InternalErr(err, "failed to start mfa")
	}
	return &MFAChallengeResponse{Status: statusMFARequired, MFAToken: raw, ExpiresAt: expires}, nil
}

// VerifyMFA completes a challenge with a TOTP or backup code and starts the session.
func (s *Service) VerifyMFA(ctx context.Context, req MFAVerifyRequest, lc LoginContext) (*AuthResponse, error) {
	expired := apierr.UnauthorizedCode("mfa_session_expired", "this sign-in has expired; please start again")

	ch, err := s.challengeRepo.GetOne(ctx, store.QueryOpts{
		Filters: map[string]any{"token_hash": platformauth.HashToken(req.MFAToken)},
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, expired
	}
	if err != nil {
		return nil, apierr.InternalErr(err, "mfa lookup failed")
	}

	// Counted before the code is checked and atomically, so parallel guesses cannot share
	// one count. An exhausted, expired or spent challenge matches no row.
	now := time.Now().UTC()
	counted, err := s.challengeRepo.UpdateColumnsGuarded(ctx, ch.ID,
		map[string]any{"consumed_at": nil},
		[]store.Clause{{Expr: "attempts < ? AND expires_at > ?", Args: []any{s.mfaMaxAttempts, now}}},
		map[string]any{"attempts": gorm.Expr("attempts + 1")})
	if err != nil {
		return nil, apierr.InternalErr(err, "mfa update failed")
	}
	if !counted {
		return nil, expired
	}

	u, err := s.userRepo.GetByID(ctx, ch.UserID)
	if err != nil {
		return nil, expired
	}
	remaining, err := s.lockout.retryAfter(ctx, u.Email)
	if err != nil {
		return nil, apierr.InternalErr(err, "lockout check failed")
	}
	if remaining > 0 {
		return nil, lockedError(remaining)
	}

	usedTOTP := s.totpValid(u, req.Code)
	usedBackup := false
	err = store.WithTx(ctx, s.db, func(ctx context.Context, _ *gorm.DB) error {
		// Claimed first, so one challenge yields one session however many valid codes race.
		claimed, err := s.challengeRepo.UpdateColumnsGuarded(ctx, ch.ID,
			map[string]any{"consumed_at": nil}, nil, map[string]any{"consumed_at": now})
		if err != nil {
			return err
		}
		if !claimed {
			return errChallengeSpent
		}
		if usedTOTP {
			return nil
		}
		usedBackup, err = s.consumeBackupCode(ctx, u.ID, req.Code)
		if err != nil {
			return err
		}
		if !usedBackup {
			return errInvalidCode
		}
		return nil
	})
	switch {
	case errors.Is(err, errInvalidCode):
		s.countFailure(ctx, u.Email)
		s.record(ctx, audit.EventMFAFailed, &u.ID, lc.IP, nil)
		return nil, apierr.UnauthorizedCode("invalid_code", "that code is not valid")
	case errors.Is(err, errChallengeSpent):
		return nil, expired
	case err != nil:
		return nil, apierr.InternalErr(err, "mfa verification failed")
	}

	if err := s.lockout.clear(ctx, u.Email); err != nil {
		s.log.Error().Err(err).Msg("auth: failed to clear the login failure count")
	}
	s.record(ctx, audit.EventMFAVerified, &u.ID, lc.IP, nil)
	if usedBackup {
		s.record(ctx, audit.EventMFABackupUsed, &u.ID, lc.IP, nil)
	}
	return s.issueSession(ctx, u, ch.Method, lc)
}

var errChallengeSpent = errors.New("auth: mfa challenge already spent")

// StartEnrollment generates a secret and holds it, encrypted, until a code confirms the
// user's authenticator has it. Calling it again replaces the pending secret.
func (s *Service) StartEnrollment(ctx context.Context, userID uint) (*EnrollStartResponse, error) {
	if err := s.mfaAvailable(); err != nil {
		return nil, err
	}
	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, apierr.InternalErr(err, "user lookup failed")
	}
	if u.MFAEnrolledAt != nil {
		return nil, apierr.Conflict("mfa_already_enrolled", "two-factor authentication is already on")
	}

	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.mfaIssuer, AccountName: u.Email})
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to generate mfa secret")
	}
	sealed, err := appcrypto.Encrypt(s.mfaKey, key.Secret())
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to secure mfa secret")
	}
	if err := s.userRepo.UpdateColumnsByID(ctx, u.ID, map[string]any{
		"mfa_pending_secret_enc": sealed,
		"mfa_pending_at":         time.Now().UTC(),
	}); err != nil {
		return nil, apierr.InternalErr(err, "failed to stage mfa secret")
	}

	img, err := key.Image(240, 240)
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to render qr code")
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, apierr.InternalErr(err, "failed to render qr code")
	}
	return &EnrollStartResponse{
		Secret:     key.Secret(),
		OtpauthURI: key.URL(),
		QR:         "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()),
	}, nil
}

// ConfirmEnrollment turns MFA on once a code proves the authenticator has the secret. It
// signs out the user's other sessions, since a second factor does little if a session
// someone else already holds survives it.
func (s *Service) ConfirmEnrollment(ctx context.Context, userID uint, currentSID, code, ip string) ([]string, error) {
	if err := s.mfaAvailable(); err != nil {
		return nil, err
	}
	keep, err := uuid.Parse(currentSID)
	if err != nil {
		return nil, apierr.Unauthorized("invalid session")
	}
	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, apierr.InternalErr(err, "user lookup failed")
	}
	if u.MFAEnrolledAt != nil {
		return nil, apierr.Conflict("mfa_already_enrolled", "two-factor authentication is already on")
	}
	if u.MFAPendingSecretEnc == "" || u.MFAPendingAt == nil || time.Since(*u.MFAPendingAt) > s.enrollTTL {
		return nil, apierr.BadRequest("enrollment_expired", "enrollment has expired; start again")
	}
	secret, err := appcrypto.Decrypt(s.mfaKey, u.MFAPendingSecretEnc)
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to read mfa secret")
	}
	if !totp.Validate(code, secret) {
		return nil, apierr.BadRequest("invalid_code", "that code is not valid")
	}

	var codes []string
	err = store.WithTx(ctx, s.db, func(ctx context.Context, _ *gorm.DB) error {
		enrolled, err := s.userRepo.UpdateColumnsGuarded(ctx, u.ID,
			map[string]any{"mfa_enrolled_at": nil}, nil,
			map[string]any{
				"totp_secret_enc":        u.MFAPendingSecretEnc,
				"mfa_enrolled_at":        time.Now().UTC(),
				"mfa_pending_secret_enc": "",
				"mfa_pending_at":         nil,
			})
		if err != nil {
			return apierr.InternalErr(err, "failed to enable mfa")
		}
		if !enrolled {
			return apierr.Conflict("mfa_already_enrolled", "two-factor authentication is already on")
		}
		if codes, err = s.replaceBackupCodes(ctx, u.ID); err != nil {
			return err
		}
		if _, err := sessions.RevokeAll(ctx, s.db, u.ID, keep); err != nil {
			return apierr.InternalErr(err, "failed to revoke sessions")
		}
		return s.recordRequired(ctx, auditlog.Entry{Event: audit.EventMFAEnrolled, ActorUserID: &u.ID, IP: ip})
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// Status reports whether MFA is on and how many backup codes are left.
func (s *Service) Status(ctx context.Context, userID uint) (*MFAStatusResponse, error) {
	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, apierr.InternalErr(err, "user lookup failed")
	}
	remaining, err := s.backupRepo.Count(ctx, store.QueryOpts{
		Filters: map[string]any{"user_id": userID},
		Where:   []store.Clause{{Expr: "used_at IS NULL"}},
	})
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to count backup codes")
	}
	return &MFAStatusResponse{
		Enabled:              u.MFAEnrolledAt != nil,
		EnrolledAt:           u.MFAEnrolledAt,
		BackupCodesRemaining: remaining,
		BackupCodesTotal:     s.backupCount,
	}, nil
}

// RegenerateBackupCodes replaces the user's codes. It needs a current TOTP code, because
// fresh backup codes are a permanent second factor and an access token alone, which could
// be stolen, should not be enough to mint them.
func (s *Service) RegenerateBackupCodes(ctx context.Context, userID uint, code, ip string) ([]string, error) {
	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, apierr.InternalErr(err, "user lookup failed")
	}
	if u.MFAEnrolledAt == nil {
		return nil, apierr.BadRequest("mfa_not_enrolled", "two-factor authentication is not on")
	}
	if err := s.checkStepUp(ctx, u, code, ip); err != nil {
		return nil, err
	}
	var codes []string
	err = store.WithTx(ctx, s.db, func(ctx context.Context, _ *gorm.DB) error {
		var err error
		if codes, err = s.replaceBackupCodes(ctx, u.ID); err != nil {
			return err
		}
		return s.recordRequired(ctx, auditlog.Entry{Event: audit.EventMFABackupRegenerated, ActorUserID: &u.ID, IP: ip})
	})
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// AdminResetMFA clears a user's MFA and signs them out. It needs a TOTP code from the
// admin: this is the step someone with a hijacked admin session would take to strip a
// target's second factor, so the session alone must not be enough.
func (s *Service) AdminResetMFA(ctx context.Context, adminID uint, targetUUID, stepUpCode, ip string) error {
	admin, err := s.userRepo.GetByID(ctx, adminID)
	if err != nil {
		return apierr.InternalErr(err, "user lookup failed")
	}
	if admin.MFAEnrolledAt == nil {
		return apierr.ForbiddenCode("step_up_required", "turn on two-factor authentication before performing this action")
	}
	if err := s.checkStepUp(ctx, admin, stepUpCode, ip); err != nil {
		return err
	}

	id, err := uuid.Parse(targetUUID)
	if err != nil {
		return apierr.NotFound("user_not_found", "user not found")
	}
	target, err := s.userRepo.GetByUUID(ctx, id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return apierr.NotFound("user_not_found", "user not found")
	}
	if err != nil {
		return apierr.InternalErr(err, "user lookup failed")
	}

	err = store.WithTx(ctx, s.db, func(ctx context.Context, tx *gorm.DB) error {
		if err := s.userRepo.UpdateColumnsByID(ctx, target.ID, map[string]any{
			"totp_secret_enc":        "",
			"mfa_enrolled_at":        nil,
			"mfa_pending_secret_enc": "",
			"mfa_pending_at":         nil,
		}); err != nil {
			return apierr.InternalErr(err, "failed to reset mfa")
		}
		if err := tx.Unscoped().Where("user_id = ?", target.ID).Delete(&mfa.BackupCode{}).Error; err != nil {
			return apierr.InternalErr(err, "failed to remove backup codes")
		}
		if _, err := sessions.RevokeAll(ctx, s.db, target.ID, uuid.Nil); err != nil {
			return apierr.InternalErr(err, "failed to revoke sessions")
		}
		return s.recordRequired(ctx, auditlog.Entry{
			Event: audit.EventMFAReset, ActorUserID: &admin.ID, IP: ip,
			Detail: map[string]any{"target_user_uuid": target.UUID.String()},
		})
	})
	if err != nil {
		return err
	}

	s.enqueue(func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, jobTimeout)
		defer cancel()
		return s.mailer.Send(ctx, target.Email, "Two-factor authentication was turned off",
			`<p>An administrator turned off two-factor authentication on this account and signed it out everywhere.</p>`+
				`<p>If you did not ask for this, contact your administrator.</p>`)
	})
	return nil
}

// checkStepUp demands a current TOTP code. Failures count toward lockout, because a
// stolen access token could otherwise guess at this endpoint unthrottled.
func (s *Service) checkStepUp(ctx context.Context, u *user.User, code, ip string) error {
	remaining, err := s.lockout.retryAfter(ctx, u.Email)
	if err != nil {
		return apierr.InternalErr(err, "lockout check failed")
	}
	if remaining > 0 {
		return lockedError(remaining)
	}
	if !s.totpValid(u, code) {
		s.countFailure(ctx, u.Email)
		s.record(ctx, audit.EventMFAFailed, &u.ID, ip, map[string]any{"step_up": true})
		return apierr.ForbiddenCode("step_up_required", "that code is not valid")
	}
	return nil
}

// replaceBackupCodes swaps the user's codes for new ones. Call it inside a transaction.
func (s *Service) replaceBackupCodes(ctx context.Context, userID uint) ([]string, error) {
	tx, ok := store.TxFromContext(ctx)
	if !ok {
		return nil, apierr.Internal("backup codes must be replaced inside a transaction")
	}
	if err := tx.WithContext(ctx).Unscoped().Where("user_id = ?", userID).Delete(&mfa.BackupCode{}).Error; err != nil {
		return nil, apierr.InternalErr(err, "failed to remove backup codes")
	}
	codes := make([]string, 0, s.backupCount)
	for i := 0; i < s.backupCount; i++ {
		code, err := generateBackupCode()
		if err != nil {
			return nil, apierr.InternalErr(err, "failed to generate backup codes")
		}
		if err := s.backupRepo.Create(ctx, &mfa.BackupCode{UserID: userID, CodeHash: hashBackupCode(code)}); err != nil {
			return nil, apierr.InternalErr(err, "failed to store backup codes")
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// consumeBackupCode spends a code. The compare-and-set is what makes it single-use: of
// two requests racing with one code, only one matches a row.
func (s *Service) consumeBackupCode(ctx context.Context, userID uint, code string) (bool, error) {
	bc, err := s.backupRepo.GetOne(ctx, store.QueryOpts{
		Filters: map[string]any{"user_id": userID, "code_hash": hashBackupCode(code)},
		Where:   []store.Clause{{Expr: "used_at IS NULL"}},
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return s.backupRepo.UpdateColumnsGuarded(ctx, bc.ID,
		map[string]any{"used_at": nil}, nil, map[string]any{"used_at": time.Now().UTC()})
}

// hashBackupCode ignores case and formatting, so a code is accepted however it is typed.
func hashBackupCode(code string) string {
	normalized := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(code))
	return platformauth.HashToken(normalized)
}

// generateBackupCode renders random bytes as four dash-separated groups of four base32
// characters.
func generateBackupCode() (string, error) {
	raw := make([]byte, backupCodeBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return enc[:4] + "-" + enc[4:8] + "-" + enc[8:12] + "-" + enc[12:16], nil
}
