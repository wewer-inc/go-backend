package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Issuer creates signed JWT tokens.
type Issuer interface {
	IssueAccessToken(userUUID string) (string, error)
	IssueRefreshToken(userUUID string) (string, error)
}

type JWTIssuer struct {
	secret             []byte
	issuer             string
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
}

func NewJWTIssuer(secret, issuer string, accessExpiry, refreshExpiry time.Duration) *JWTIssuer {
	return &JWTIssuer{
		secret:             []byte(secret),
		issuer:             issuer,
		accessTokenExpiry:  accessExpiry,
		refreshTokenExpiry: refreshExpiry,
	}
}

func (i *JWTIssuer) IssueAccessToken(userUUID string) (string, error) {
	return i.sign(userUUID, i.accessTokenExpiry)
}

func (i *JWTIssuer) IssueRefreshToken(userUUID string) (string, error) {
	return i.sign(userUUID, i.refreshTokenExpiry)
}

func (i *JWTIssuer) sign(subject string, expiry time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": subject,
		"iss": i.issuer,
		"iat": now.Unix(),
		"exp": now.Add(expiry).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(i.secret)
}
