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
	UseAccess TokenUse = "access"
	// UseRefresh is no longer minted: refresh tokens are opaque now. It stays so a signed
	// refresh JWT from before that change keeps being refused as a bearer credential.
	UseRefresh TokenUse = "refresh"
)

// IssuedToken is the result of minting a token. JTI is the unique token id, used to
// denylist the token later.
type IssuedToken struct {
	Token     string
	JTI       string
	ExpiresAt time.Time
}

// AccessParams is what an access token is minted from.
type AccessParams struct {
	Subject string // user UUID
	SID     string // session UUID
}

// tokenClaims is the full claim set carried by every token.
type tokenClaims struct {
	TokenUse TokenUse `json:"token_use"`
	SID      string   `json:"sid,omitempty"`
	jwt.RegisteredClaims
}

// Issuer signs access tokens only. A refresh token is an opaque value tracked in the
// sessions table, so nothing in this package handles one.
type Issuer interface {
	IssueAccessToken(p AccessParams) (IssuedToken, error)
}

type JWTIssuer struct {
	secret            []byte
	issuer            string
	audience          string
	accessTokenExpiry time.Duration
}

func NewJWTIssuer(secret, issuer, audience string, accessExpiry time.Duration) *JWTIssuer {
	return &JWTIssuer{
		secret:            []byte(secret),
		issuer:            issuer,
		audience:          audience,
		accessTokenExpiry: accessExpiry,
	}
}

func (i *JWTIssuer) IssueAccessToken(p AccessParams) (IssuedToken, error) {
	now := time.Now()
	expiresAt := now.Add(i.accessTokenExpiry)
	jti := uuid.NewString()

	claims := tokenClaims{
		TokenUse: UseAccess,
		SID:      p.SID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   p.Subject,
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
