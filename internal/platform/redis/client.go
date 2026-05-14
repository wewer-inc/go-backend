package redis

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"

	goredis "github.com/redis/go-redis/v9"
)

type Client struct {
	cfg    config.RedisConfig
	client *goredis.Client
}

// NewClient creates a new Redis client with the provided configuration.
// It validates the configuration parameters and returns an error if any required
// fields are missing or invalid
//
// The client supports optional TLS configuration when TLSEnable is true,
// using TLS 1.2 as the minimum version.
//
// Parameters:
//   - cfg: RedisConfig containing connection parameters including address,
//     authentication, database selection, connection pooling, and timeout settings
//
// Returns:
//   - *Client: configured Redis client wrapper
//   - error: validation error if configuration is invalid, nil on success
func NewClient(cfg config.RedisConfig) (*Client, error) {
	if cfg.Addr == "" {
		return nil, errors.New("redis: REDIS_ADDR is required")
	}
	if cfg.DB < 0 {
		return nil, errors.New("redis: REDIS_DB must be >= 0")
	}
	if cfg.PoolSize < 0 {
		return nil, errors.New("redis: REDIS_POOL_SIZE must be >= 0")
	}
	if cfg.MinIdleConns < 0 {
		return nil, errors.New("redis: REDIS_MIN_IDLE_CONNS must be >= 0")
	}

	opts := &goredis.Options{
		Addr:         cfg.Addr,
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	if cfg.TLSEnable {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	rdb := goredis.NewClient(opts)

	return &Client{
		cfg:    cfg,
		client: rdb,
	}, nil
}

// HealthCheck performs a health check on the Redis connection by sending a PING command.
// It returns an error if the Redis server is unreachable or not responding properly.
// The context can be used to set timeouts or cancel the operation.
func (c *Client) HealthCheck(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// Close closes the Redis client connection and releases any associated resources.
// It returns an error if the connection cannot be closed properly.
func (c *Client) Close() error {
	return c.client.Close()
}

// Raw returns the underlying go-redis client instance.
// This method provides direct access to the redis client for operations
// that are not wrapped by the Client struct.
func (c *Client) Raw() *goredis.Client {
	return c.client
}
