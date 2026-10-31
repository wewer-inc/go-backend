package crypto

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const secret = "0123456789abcdef0123456789abcdef"

func key(t *testing.T, s string) []byte {
	t.Helper()
	k, err := DeriveKey(s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestDecryptRecoversWhatEncryptSealed(t *testing.T) {
	k := key(t, secret)
	sealed, err := Encrypt(k, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "JBSWY3DPEHPK3PXP") {
		t.Fatal("ciphertext contains the plaintext")
	}
	got, err := Decrypt(k, sealed)
	if err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDeriveKeyRefusesAShortSecret(t *testing.T) {
	for _, s := range []string{"", "short", strings.Repeat("a", MinSecretLength-1)} {
		if _, err := DeriveKey(s); !errors.Is(err, ErrSecretTooShort) {
			t.Errorf("%q: %v", s, err)
		}
	}
	if k := key(t, strings.Repeat("a", MinSecretLength)); len(k) != 32 {
		t.Fatalf("key length %d", len(k))
	}
}

func TestEachEncryptionUsesAFreshNonce(t *testing.T) {
	k := key(t, secret)
	a, _ := Encrypt(k, "same")
	b, _ := Encrypt(k, "same")
	if a == b {
		t.Fatal("two encryptions of one value must differ")
	}
}

func TestDecryptRefuses(t *testing.T) {
	k := key(t, secret)
	sealed, err := Encrypt(k, "value")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(sealed)
	raw[len(raw)-1] ^= 0xff

	if _, err := Decrypt(key(t, strings.Repeat("b", 32)), sealed); err == nil {
		t.Error("the wrong key decrypted")
	}
	if _, err := Decrypt(k, base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Error("altered ciphertext decrypted")
	}
	if _, err := Decrypt(k, "not base64!"); err == nil {
		t.Error("garbage decrypted")
	}
	if _, err := Decrypt(k, base64.StdEncoding.EncodeToString([]byte("x"))); err == nil {
		t.Error("a too-short value decrypted")
	}
}
