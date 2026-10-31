package auth

import (
	"errors"
	"unicode/utf8"
)

// The password policy is length only. Forced mixes of character classes push people
// toward predictable substitutions, and length is what actually costs an attacker.
const (
	// PasswordMinLength is in characters, so a passphrase in any script counts fairly.
	PasswordMinLength = 12
	// PasswordMaxBytes is bcrypt's limit: it ignores or refuses anything longer. It is in
	// bytes, because that is what bcrypt counts.
	PasswordMaxBytes = 72
)

// Codes returned by PasswordProblems, for a client to translate.
const (
	PasswordTooShort = "min_length"
	PasswordTooLong  = "max_length"
)

// ErrWeakPassword is returned by ValidatePassword.
var ErrWeakPassword = errors.New("password must be at least 12 characters and at most 72 bytes")

// PasswordProblems lists a code for each rule pw breaks. A password that satisfies the
// policy gets nil.
func PasswordProblems(pw string) []string {
	var out []string
	if utf8.RuneCountInString(pw) < PasswordMinLength {
		out = append(out, PasswordTooShort)
	}
	if len(pw) > PasswordMaxBytes {
		out = append(out, PasswordTooLong)
	}
	return out
}

// ValidatePassword returns ErrWeakPassword when pw breaks the policy.
func ValidatePassword(pw string) error {
	if len(PasswordProblems(pw)) > 0 {
		return ErrWeakPassword
	}
	return nil
}
