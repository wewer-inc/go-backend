package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const secret = "test-secret-test-secret-test-secret"

func TestIssuedAccessTokenVerifiesWithItsClaims(t *testing.T) {
	iss := NewJWTIssuer(secret, "iss", "aud", time.Minute)
	tok, err := iss.IssueAccessToken(AccessParams{Subject: "user", SID: "sess"})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewJWTVerifier(secret, "iss", "aud").Verify(tok.Token)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "user" || c.SID != "sess" || c.TokenUse != UseAccess || c.JTI != tok.JTI {
		t.Fatalf("claims = %+v", c)
	}
}

func TestVerifierRefuses(t *testing.T) {
	good, err := NewJWTIssuer(secret, "iss", "aud", time.Minute).IssueAccessToken(AccessParams{Subject: "u"})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := NewJWTIssuer(secret, "iss", "aud", -time.Minute).IssueAccessToken(AccessParams{Subject: "u"})
	if err != nil {
		t.Fatal(err)
	}
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, tokenClaims{
		TokenUse:         UseAccess,
		RegisteredClaims: jwt.RegisteredClaims{Subject: "u", Issuer: "iss", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))},
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name     string
		verifier *JWTVerifier
		token    string
		want     error
	}{
		{"wrong secret", NewJWTVerifier("another-secret-another-secret-xx", "iss", "aud"), good.Token, ErrInvalidToken},
		{"wrong issuer", NewJWTVerifier(secret, "other", "aud"), good.Token, ErrInvalidIssuer},
		{"wrong audience", NewJWTVerifier(secret, "iss", "other"), good.Token, ErrInvalidToken},
		{"expired", NewJWTVerifier(secret, "iss", "aud"), expired.Token, ErrExpiredToken},
		{"alg none", NewJWTVerifier(secret, "iss", ""), none, ErrInvalidToken},
		{"not a jwt", NewJWTVerifier(secret, "iss", "aud"), "opaque", ErrInvalidToken},
	}
	for _, tc := range cases {
		if _, err := tc.verifier.Verify(tc.token); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestOpaqueTokensAreRandomAndHashStably(t *testing.T) {
	a, err := GenerateOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b || len(a) < 40 {
		t.Fatalf("tokens: %q %q", a, b)
	}
	if HashToken(a) != HashToken(a) || HashToken(a) == HashToken(b) || HashToken(a) == a {
		t.Fatal("hash is not a stable one-way function of the token")
	}
}
