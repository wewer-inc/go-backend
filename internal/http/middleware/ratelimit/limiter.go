package ratelimit

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	platformredis "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/redis"
	goredis "github.com/redis/go-redis/v9"
)

type Limiter struct {
	rdb *goredis.Client
}

func NewLimiter(rc *platformredis.Client) *Limiter {
	return &Limiter{
		rdb: rc.Raw(),
	}
}

// Allow checks if a request identified by the given key is allowed under the specified rate limit bucket configuration.
// It uses a Redis-based Generic Cell Rate Algorithm (GCRA) implementation via Lua script to perform the rate limiting check.
//
// Parameters:
//   - ctx: Context for the operation, used for Redis operations and cancellation
//   - key: Unique identifier for the rate limit bucket (e.g., user ID, IP address)
//   - bucket: Rate limit configuration containing RPM (requests per minute) and burst capacity
//
// Returns:
//   - allowed: true if the request is allowed, false if rate limited
//   - retryAfterSeconds: when denied, the number of seconds to wait before retrying (minimum 1 second)
//   - err: error if the operation fails due to invalid parameters or Redis issues
//
// The function validates inputs and returns errors for:
//   - nil Redis client
//   - empty key
//   - invalid RPM (must be > 0)
//   - invalid burst (must be >= 0)
//   - Redis communication errors
//   - malformed Lua script responses
//
// When a request is rate limited, the retry-after value is calculated from milliseconds to seconds
// and enforced to be at least 1 second to comply with HTTP semantics.
func (l *Limiter) Allow(ctx context.Context, key string, bucket config.RateLimitBucketConfig) (allowed bool, retryAfterSeconds int, err error) {
	if l.rdb == nil {
		return false, 0, errors.New("ratelimit: redis client is nil")
	}

	if key == "" {
		return false, 0, errors.New("ratelimit: key is empty")
	}

	if bucket.RPM <= 0 {
		// If misconfigured, fail closed (safe)
		return false, 1, errors.New("ratelimit: RPM must be > 0")
	}

	if bucket.Burst < 0 {
		return false, 1, errors.New("ratelimit: Burst must be >= 0")
	}

	intervalMs := rpmIntervalMs(bucket.RPM)
	nowMs := time.Now().UnixMilli()

	// Lua returns: {allowed(0/1), retry_ms}
	res, evalErr := l.rdb.Eval(ctx, luaGCRALimit, []string{key}, intervalMs, bucket.Burst, nowMs).Result()
	if evalErr != nil {
		return false, 0, evalErr
	}

	arr, ok := res.([]any)
	if !ok || len(arr) < 2 {
		return false, 0, errors.New("ratelimit: unexpected redis lua response")
	}

	allowedInt, ok := toInt64(arr[0])
	if !ok {
		return false, 0, errors.New("ratelimit: invalid allowed value from lua")
	}

	retryMs, ok := toInt64(arr[1])
	if !ok {
		return false, 0, errors.New("ratelimit: invalid retry_ms value from lua")
	}

	if allowedInt == 1 {
		return true, 0, nil
	}

	// Denied: translate retry_ms into Retry-After seconds
	// Must be >= 1 seconds when denied (HTTP semantics)
	sec := int(math.Ceil(float64(retryMs) / 1000.0))
	if sec < 1 {
		sec = 1
	}

	return false, sec, nil
}

func rpmIntervalMs(rpm int) int64 {
	// 60,000 ms per minute / rpm -> interval per token in ms
	// Guard against division by zero or negative rpm
	if rpm <= 0 {
		return 60000
	}

	interval := int64(60000 / rpm)
	if interval < 1 {
		interval = 1
	}

	return interval
}

func toInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case int64:
		return t, true
	case int:
		return int64(t), true
	case float64:
		return int64(t), true
	case string:
		n, err := parseInt64(t)
		return n, err == nil
	default:
		return 0, false
	}
}

func parseInt64(s string) (int64, error) {
	var neg bool
	if s == "" {
		return 0, errors.New("empty")
	}
	if s[0] == '-' {
		neg = true
		s = s[1:]
		if s == "" {
			return 0, errors.New("invalid")
		}
	}
	var n int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, errors.New("invalid")
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

// GCRA / leaky-bucket style limiter.
// Stores "tat" (theoretical arrival time) in ms at KEY.
// Atomic decision per request.
//
// ARGV:
// 1 = interval_ms (int)
// 2 = burst (int)
// 3 = now_ms (int)
//
// returns {allowed(0/1), retry_ms}
const luaGCRALimit = `
local key = KEYS[1]

local interval = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

if interval == nil or interval <= 0 then
  return {0, 1000}
end
if burst == nil or burst < 0 then
  return {0, 1000}
end
if now == nil or now < 0 then
  return {0, 1000}
end

-- tat = theoretical arrival time (ms)
local tat = tonumber(redis.call("GET", key))
if tat == nil then
  tat = 0
end

-- allow if now >= (tat - burst * interval)
local burst_offset = burst * interval
local allow_at = tat - burst_offset

if now < allow_at then
  local retry_ms = allow_at - now
  if retry_ms < 0 then retry_ms = 0 end
  return {0, retry_ms}
end

local new_tat = tat
if now > new_tat then
  new_tat = now
end
new_tat = new_tat + interval

-- TTL: enough to cover burst window + slack
local ttl = (burst + 2) * interval
if ttl < 1000 then ttl = 1000 end

redis.call("SET", key, new_tat, "PX", ttl)

return {1, 0}
`
