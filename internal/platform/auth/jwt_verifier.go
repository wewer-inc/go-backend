package auth

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

var (
	ErrInvalidToken   = errors.New("invalid token")
	ErrExpiredToken   = errors.New("expired token")
	ErrInvalidIssuer  = errors.New("invalid issuer")
	ErrMissingSubject = errors.New("missing subject claim")
)

type Verifier interface {
	Verify(token string) (string, error)
}

type JWTVerifier struct {
	secret []byte
	issuer string
}

func NewJWTVerifier(secret, issuer string) *JWTVerifier {
	return &JWTVerifier{
		secret: []byte(secret),
		issuer: issuer,
	}
}

// Verify validates a JWT token string and returns the subject claim.
// It performs the following validations:
// - Verifies the token signature using HMAC SHA256 signing method
// - Checks token expiration and validity
// - Validates the issuer claim if configured
// - Extracts and validates the subject claim
//
// Parameters:
//   - tokenString: The JWT token string to verify
//
// Returns:
//   - string: The subject (sub) claim from the token if validation succeeds
//   - error: Specific error types for different validation failures:
//   - ErrExpiredToken: Token has expired
//   - ErrInvalidToken: Token is malformed or invalid
//   - ErrInvalidIssuer: Token issuer doesn't match expected issuer
//   - ErrMissingSubject: Token missing or empty subject claim
func (v *JWTVerifier) Verify(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		// Enforce signing method HMAC SHA256
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.secret, nil
	})

	if err != nil {
		// jwt library already differentiates expired tokens
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", ErrExpiredToken
		}
		return "", ErrInvalidToken
	}

	if !token.Valid {
		return "", ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return "", ErrInvalidToken
	}

	// Validate issuer
	if v.issuer != "" {
		iss, ok := claims["iss"].(string)
		if !ok || iss != v.issuer {
			return "", ErrInvalidIssuer
		}
	}

	// Extract subject
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", ErrMissingSubject
	}

	return sub, nil
}
