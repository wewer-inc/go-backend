package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenUse identifies what a token may be used for. Stamping this into the
// token and enforcing it at each call site prevents a long-lived refresh token
// from being replayed as a short-lived access bearer credential.
type TokenUse string

const (
	UseAccess  TokenUse = "access"
	UseRefresh TokenUse = "refresh"
)

// IssuedToken is the result of minting a token. JTI is the unique token id —
// callers persist it (e.g. to key a refresh session in Redis) and use it to
// revoke the token later.
type IssuedToken struct {
	Token     string
	JTI       string
	ExpiresAt time.Time
}

// tokenClaims is the full claim set carried by every token.
type tokenClaims struct {
	TokenUse TokenUse `json:"token_use"`
	jwt.RegisteredClaims
}

// Issuer creates signed JWT tokens.
type Issuer interface {
	IssueAccessToken(subject string) (IssuedToken, error)
	IssueRefreshToken(subject string) (IssuedToken, error)
}

type JWTIssuer struct {
	secret             []byte
	issuer             string
	audience           string
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
}

func NewJWTIssuer(secret, issuer, audience string, accessExpiry, refreshExpiry time.Duration) *JWTIssuer {
	return &JWTIssuer{
		secret:             []byte(secret),
		issuer:             issuer,
		audience:           audience,
		accessTokenExpiry:  accessExpiry,
		refreshTokenExpiry: refreshExpiry,
	}
}

func (i *JWTIssuer) IssueAccessToken(subject string) (IssuedToken, error) {
	return i.sign(subject, UseAccess, i.accessTokenExpiry)
}

func (i *JWTIssuer) IssueRefreshToken(subject string) (IssuedToken, error) {
	return i.sign(subject, UseRefresh, i.refreshTokenExpiry)
}

func (i *JWTIssuer) sign(subject string, use TokenUse, expiry time.Duration) (IssuedToken, error) {
	now := time.Now()
	expiresAt := now.Add(expiry)
	jti := uuid.NewString()

	claims := tokenClaims{
		TokenUse: use,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    i.issuer,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	if i.audience != "" {
		claims.Audience = jwt.ClaimStrings{i.audience}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(i.secret)
	if err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{Token: signed, JTI: jti, ExpiresAt: expiresAt}, nil
}
