package auth

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordPolicy(t *testing.T) {
	cases := []struct {
		name string
		pw   string
		want []string
	}{
		{"empty", "", []string{PasswordTooShort}},
		{"one short", strings.Repeat("a", 11), []string{PasswordTooShort}},
		{"exactly the minimum", strings.Repeat("a", 12), nil},
		{"no composition rules", "correct horse battery", nil},
		{"exactly the maximum", strings.Repeat("a", 72), nil},
		{"one long", strings.Repeat("a", 73), []string{PasswordTooLong}},
		// Twelve characters of three bytes each: short by bytes would be the wrong measure.
		{"multibyte counts characters for the minimum", strings.Repeat("日", 12), nil},
		// 25 characters is 75 bytes, which bcrypt refuses.
		{"multibyte counts bytes for the maximum", strings.Repeat("日", 25), []string{PasswordTooLong}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PasswordProblems(tc.pw); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("problems = %v, want %v", got, tc.want)
			}
			err := ValidatePassword(tc.pw)
			if (err == nil) != (tc.want == nil) || (err != nil && !errors.Is(err, ErrWeakPassword)) {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// Anything the policy accepts must be hashable, and anything longer must not reach bcrypt.
func TestPolicyMaximumMatchesBcrypt(t *testing.T) {
	if _, err := bcrypt.GenerateFromPassword([]byte(strings.Repeat("a", PasswordMaxBytes)), bcrypt.MinCost); err != nil {
		t.Fatalf("the longest accepted password failed to hash: %v", err)
	}
	if _, err := bcrypt.GenerateFromPassword([]byte(strings.Repeat("a", PasswordMaxBytes+1)), bcrypt.MinCost); err == nil {
		t.Fatal("bcrypt's limit has moved; revisit PasswordMaxBytes")
	}
}
