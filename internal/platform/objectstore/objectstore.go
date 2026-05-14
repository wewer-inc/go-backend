package objectstore

import (
	"context"
	"time"
)

type HeadObjectResult struct {
	ETag        string
	SizeBytes   int64
	ContentType string
}

type PresignPutParams struct {
	Bucket      string
	Key         string
	ContentType string
	ExpiresIn   time.Duration
	// Note: strict Content-Length enforcement via presign is limited in S3.
	// We enforce size on Complete using HeadObject.
}

type PresignGetParams struct {
	Bucket    string
	Key       string
	ExpiresIn time.Duration
}

type Store interface {
	HealthCheck(ctx context.Context) error
	PresignPut(ctx context.Context, p PresignPutParams) (string, error)
	PresignGet(ctx context.Context, p PresignGetParams) (string, error)
	HeadObject(ctx context.Context, bucket, key string) (HeadObjectResult, error)
}
