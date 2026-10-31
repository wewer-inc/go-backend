// Package crypto encrypts values the application must store yet read back, TOTP seeds
// being the present case, using AES-256-GCM under a single key taken from configuration.
// Adopting a key management service later would change where callers get that key, while
// the stored columns stay as they are.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// MinSecretLength is the shortest configured secret DeriveKey accepts. SHA-256 sizes a
// secret correctly but adds no strength, so a short one would make a weak key.
const MinSecretLength = 32

// ErrSecretTooShort is returned by DeriveKey.
var ErrSecretTooShort = fmt.Errorf("crypto: secret must be at least %d characters", MinSecretLength)

// DeriveKey hashes a configured secret down to the 32 bytes AES-256 needs.
func DeriveKey(secret string) ([]byte, error) {
	if len(secret) < MinSecretLength {
		return nil, ErrSecretTooShort
	}
	digest := sha256.Sum256([]byte(secret))
	return digest[:], nil
}

// Encrypt returns plaintext sealed under key with AES-256-GCM, encoded as standard base64
// of the random nonce followed by the ciphertext and its tag.
func Encrypt(key []byte, plaintext string) (string, error) {
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a value produced by Encrypt, and fails if the key is wrong or the value
// was altered.
func Decrypt(key []byte, encoded string) (string, error) {
	aead, err := newGCM(key)
	if err != nil {
		return "", err
	}
	sealed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	nonceLen := aead.NonceSize()
	if len(sealed) < nonceLen {
		return "", errors.New("crypto: ciphertext too short")
	}
	plaintext, err := aead.Open(nil, sealed[:nonceLen], sealed[nonceLen:], nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
