package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
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
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// statusMFARequired is the status on a challenge response.
const statusMFARequired = "mfa_required"

// backupCodeBytes is 80 bits. Backup codes are hashed with fast SHA-256, so they need
// enough entropy that a leaked table cannot be brute forced.
const backupCodeBytes = 10

// totpPeriod is the length of a TOTP time step, in seconds.
const totpPeriod = 30

// reauthWindow is how recently an account with no password must have signed in to make a
// change that would otherwise need its password.
const reauthWindow = 5 * time.Minute

var errInvalidCode = errors.New("auth: invalid mfa code")

func (s *Service) mfaAvailable() error {
	if s.mfaKey == nil {
		return apierr.ServiceUnavailable("mfa_unavailable", "two-factor authentication is not configured on this server")
	}
	return nil
}

// matchTOTPStep finds the time step a code belongs to, within one step either side of now
// for clock drift. A plain validity check is not enough: refusing a replay needs to know
// which step was used.
func matchTOTPStep(secret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	var step int64
	found := false
	// Every candidate is compared, newest last. In the rare case one code fits two steps,
	// the newest is the one that does not falsely read as a replay.
	for offset := -1; offset <= 1; offset++ {
		at := now.Add(time.Duration(offset) * totpPeriod * time.Second)
		want, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{
			Period: totpPeriod, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			step = at.Unix() / totpPeriod
			found = true
		}
	}
	return step, found
}

// totpStep matches a code against the user's stored secret. An undecryptable secret is
// logged and reads as a wrong code: backup codes still work, and the account is not locked
// out of them by a rotated key.
func (s *Service) totpStep(u *user.User, code string) (int64, bool) {
	if u.TOTPSecretEnc == "" || s.mfaKey == nil {
		return 0, false
	}
	secret, err := appcrypto.Decrypt(s.mfaKey, u.TOTPSecretEnc)
	if err != nil {
		s.log.Error().Err(err).Uint("user_id", u.ID).Msg("auth: could not decrypt a totp secret")
		return 0, false
	}
	return matchTOTPStep(secret, code, time.Now())
}

// consumeTOTPStep advances the user's last accepted step. A TOTP code is otherwise good
// for its whole window, so one seen over a shoulder could be used again. The compare-and-set
// means that of two requests with one code, only one matches a row, and a code from a step
// at or before the stored one matches none.
func (s *Service) consumeTOTPStep(ctx context.Context, userID uint, step int64) (bool, error) {
	return s.userRepo.UpdateColumnsGuarded(ctx, userID, nil,
		[]store.Clause{{Expr: "totp_last_step IS NULL OR totp_last_step < ?", Args: []any{step}}},
		map[string]any{"totp_last_step": step})
}

// checkIdentity is the re-authentication in front of changes that would let a stolen
// session keep the account: the current password, or, for an account that has none, a
// session signed in moments ago. Refreshing does not make a session recent, so a stolen one
// cannot refresh its way past this.
func (s *Service) checkIdentity(ctx context.Context, u *user.User, sid, password string) error {
	if u.PasswordHash != "" {
		return s.checkCurrentPassword(ctx, u, password)
	}
	sess, err := s.sessionByUUID(ctx, sid)
	if err != nil {
		return apierr.InternalErr(err, "session lookup failed")
	}
	if time.Since(sess.CreatedAt) > reauthWindow {
		return apierr.ForbiddenCode("reauthentication_required", "sign in again to make this change")
	}
	return nil
}

// startChallenge creates the challenge an enrolled user must pass to get a session, and
// retires any earlier one, so a user has at most one live. The row lock keeps that true
// when two sign-ins start at once: otherwise neither would see the other's new challenge.
func (s *Service) startChallenge(ctx context.Context, u *user.User, method session.LoginMethod) (*MFAChallengeResponse, error) {
	raw, err := platformauth.GenerateOpaqueToken()
	if err != nil {
		return nil, apierr.InternalErr(err, "failed to start mfa")
	}
	expires := time.Now().UTC().Add(s.challengeTTL)
	err = store.WithTx(ctx, s.db, func(ctx context.Context, tx *gorm.DB) error {
		var locked user.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Select("id").Take(&locked, u.ID).Error; err != nil {
			return err
		}
		if err := tx.Model(&mfa.Challenge{}).
			Where("user_id = ? AND consumed_at IS NULL", u.ID).
			Update("consumed_at", time.Now().UTC()).Error; err != nil {
			return err
		}
		return s.challengeRepo.Create(ctx, &mfa.Challenge{
			UserID:    u.ID,
			TokenHash: platformauth.HashToken(raw),
			Method:    method,
			ExpiresAt: expires,
		})
	})
	if err != nil {
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
	if err := s.reserveAttempt(ctx, u.Email); err != nil {
		return nil, err
	}

	step, usedTOTP := s.totpStep(u, req.Code)
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
			fresh, err := s.consumeTOTPStep(ctx, u.ID, step)
			if err != nil {
				return err
			}
			if !fresh {
				return errInvalidCode // a replay; rolling back leaves the challenge usable
			}
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
		s.record(ctx, audit.EventMFAFailed, &u.ID, lc.IP, nil)
		return nil, apierr.UnauthorizedCode("invalid_code", "that code is not valid")
	case errors.Is(err, errChallengeSpent):
		return nil, expired
	case err != nil:
		return nil, apierr.InternalErr(err, "mfa verification failed")
	}

	s.clearAttempts(ctx, u.Email)
	s.record(ctx, audit.EventMFAVerified, &u.ID, lc.IP, nil)
	if usedBackup {
		s.record(ctx, audit.EventMFABackupUsed, &u.ID, lc.IP, nil)
	}
	return s.issueSession(ctx, u, ch.Method, lc)
}

var errChallengeSpent = errors.New("auth: mfa challenge already spent")

// StartEnrollment generates a secret and holds it, encrypted, until a code confirms the
// user's authenticator has it. Calling it again replaces the pending secret. It needs
// re-authentication: otherwise a stolen session could put the thief's device on the account
// and, by signing out other sessions, lock the owner out of it.
func (s *Service) StartEnrollment(ctx context.Context, userID uint, currentSID, password string) (*EnrollStartResponse, error) {
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
	if err := s.checkIdentity(ctx, u, currentSID, password); err != nil {
		return nil, err
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: s.mfaIssuer, AccountName: u.Email, Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
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
	step, ok := matchTOTPStep(secret, code, time.Now())
	if !ok {
		return nil, apierr.BadRequest("invalid_code", "that code is not valid")
	}

	var codes []string
	err = store.WithTx(ctx, s.db, func(ctx context.Context, _ *gorm.DB) error {
		enrolled, err := s.userRepo.UpdateColumnsGuarded(ctx, u.ID,
			map[string]any{"mfa_enrolled_at": nil}, nil,
			map[string]any{
				"totp_secret_enc":        u.MFAPendingSecretEnc,
				"totp_last_step":         step, // the code that proved enrollment is spent
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
	s.mailNotice(u.Email, "Two-factor authentication was turned on",
		`<p>Two-factor authentication was just turned on for this account, and other devices were signed out.</p>`+
			`<p>If this was not you, contact your administrator now.</p>`)
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

// RegenerateBackupCodes issues a new set of codes and voids the old set. The caller must
// prove their identity again and supply a current TOTP code: backup codes never expire, so
// a stolen access token on its own must not be able to produce them.
func (s *Service) RegenerateBackupCodes(ctx context.Context, userID uint, currentSID, password, code, ip string) ([]string, error) {
	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, apierr.InternalErr(err, "user lookup failed")
	}
	if u.MFAEnrolledAt == nil {
		return nil, apierr.BadRequest("mfa_not_enrolled", "two-factor authentication is not on")
	}
	if err := s.checkIdentity(ctx, u, currentSID, password); err != nil {
		return nil, err
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
	s.mailNotice(u.Email, "Your backup codes were replaced",
		`<p>New two-factor backup codes were just generated for this account, and the old ones no longer work.</p>`+
			`<p>If this was not you, contact your administrator now.</p>`)
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
			"totp_last_step":         nil,
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

	s.mailNotice(target.Email, "Two-factor authentication was turned off",
		`<p>An administrator turned off two-factor authentication on this account and signed it out everywhere.</p>`+
			`<p>If you did not ask for this, contact your administrator.</p>`)
	return nil
}

// checkStepUp demands a current TOTP code, spending it so it cannot be used again. Failures
// count toward lockout, because a stolen access token could otherwise guess here unthrottled.
func (s *Service) checkStepUp(ctx context.Context, u *user.User, code, ip string) error {
	if err := s.reserveAttempt(ctx, u.Email); err != nil {
		return err
	}
	refused := func() error {
		s.record(ctx, audit.EventMFAFailed, &u.ID, ip, map[string]any{"step_up": true})
		return apierr.ForbiddenCode("step_up_required", "that code is not valid")
	}
	step, ok := s.totpStep(u, code)
	if !ok {
		return refused()
	}
	fresh, err := s.consumeTOTPStep(ctx, u.ID, step)
	if err != nil {
		return apierr.InternalErr(err, "failed to record the code")
	}
	if !fresh {
		return refused()
	}
	s.releaseAttempt(ctx, u.Email)
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
