package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// GenerateOpaqueToken returns a random URL-safe token with 256 bits of entropy. Only its
// hash (see HashToken) is ever stored. Entropy is why a fast hash is fine here: there is
// nothing to brute force, unlike a password.
func GenerateOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken gives the form of an opaque token that is stored and looked up: its SHA-256,
// hex-encoded.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
