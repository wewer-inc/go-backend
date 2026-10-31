package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken   = errors.New("invalid token")
	ErrExpiredToken   = errors.New("expired token")
	ErrInvalidIssuer  = errors.New("invalid issuer")
	ErrMissingSubject = errors.New("missing subject claim")
)

// Claims is the validated, caller-facing view of a verified token.
type Claims struct {
	Subject   string
	TokenUse  TokenUse
	JTI       string
	SID       string
	ExpiresAt time.Time
}

type Verifier interface {
	// Verify validates signature, issuer, audience and expiry, returning the claims.
	Verify(token string) (*Claims, error)
}

type JWTVerifier struct {
	secret   []byte
	issuer   string
	audience string
}

func NewJWTVerifier(secret, issuer, audience string) *JWTVerifier {
	return &JWTVerifier{
		secret:   []byte(secret),
		issuer:   issuer,
		audience: audience,
	}
}

// Verify validates a JWT and returns its claims. It enforces the HMAC-SHA256
// signing method (blocking alg-confusion / "none" attacks), a non-empty
// subject, expiry, and — when configured — the issuer and audience claims.
//
// Note: this does NOT check token_use. Each call site is responsible for
// asserting claims.TokenUse, so nothing but an access token is accepted as one.
func (v *JWTVerifier) Verify(tokenString string) (*Claims, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithExpirationRequired(),
	}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		opts = append(opts, jwt.WithAudience(v.audience))
	}

	claims := &tokenClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return v.secret, nil
	}, opts...)

	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, ErrExpiredToken
		case errors.Is(err, jwt.ErrTokenInvalidIssuer):
			return nil, ErrInvalidIssuer
		default:
			return nil, ErrInvalidToken
		}
	}

	if claims.Subject == "" {
		return nil, ErrMissingSubject
	}

	out := &Claims{
		Subject:  claims.Subject,
		TokenUse: claims.TokenUse,
		JTI:      claims.ID,
		SID:      claims.SID,
	}
	if claims.ExpiresAt != nil {
		out.ExpiresAt = claims.ExpiresAt.Time
	}
	return out, nil
}
