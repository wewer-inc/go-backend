package ratelimit

import (
	"net"
	"strings"

	"github.com/gin-gonic/gin"
)

type Bucket string

const (
	BucketGlobal Bucket = "global"
	BucketAdmin  Bucket = "admin"
	BucketAuth   Bucket = "auth"
)

// Resolver is responsible for selecting bucket + building the redis key identity
type Resolver struct{}

func NewResolver() *Resolver {
	return &Resolver{}
}

// KeyForRequest returns the bucket and final redis key for the current request.
// If actor_user_id is > 0, it uses that as identity, otherwise falls back to IP address.
func (r *Resolver) KeyForRequest(c *gin.Context, bucket Bucket, actorUserID int64) (string, bool) {
	if actorUserID > 0 {
		return buildUserKey(bucket, actorUserID), true
	}

	ip := r.extractClientIP(c)
	if ip == "" {
		return "", false
	}
	return buildIPKey(bucket, ip), true
}

func buildUserKey(bucket Bucket, userID int64) string {
	return "rl:" + string(bucket) + ":user:" + itoa(userID)
}

func buildIPKey(bucket Bucket, ip string) string {
	return "rl:" + string(bucket) + ":ip:" + ip
}

// extractClientIP returns the client IP. It delegates to gin's ClientIP(),
// which only honours X-Forwarded-For when the immediate peer is a configured
// trusted proxy (see config.TrustedProxies / gin.SetTrustedProxies). This
// avoids the classic spoof where a client sets its own XFF to mint a fresh
// rate-limit bucket per request.
func (r *Resolver) extractClientIP(c *gin.Context) string {
	return normalizeIP(c.ClientIP())
}

func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

// itoa is a tiny helper to avoid pulling fmt into hot-path code.
func itoa(v int64) string {
	// simple base10 conversion
	if v == 0 {
		return "0"
	}

	neg := v < 0
	if neg {
		v = -v
	}

	var buf [20]byte
	i := len(buf)

	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}

	if neg {
		i--
		buf[i] = '-'
	}

	return string(buf[i:])
}
