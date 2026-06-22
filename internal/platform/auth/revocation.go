package auth

// DenylistKey returns the key used to mark an access token's jti as revoked.
// The auth service writes this key (with a TTL equal to the token's remaining
// life) on logout; the auth middleware checks it on every request. Sharing the
// helper keeps the two sides in sync.
func DenylistKey(jti string) string {
	return "jwt_denylist:" + jti
}
