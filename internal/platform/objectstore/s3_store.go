package objectstore

import (
	"context"
	"errors"
	"strings"

	config "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/config"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3Store struct {
	cfg       config.S3Config
	client    *s3.Client
	presigner *s3.PresignClient
}

// NewS3Store creates a new S3Store instance with the provided configuration.
// It loads the default AWS configuration for the specified region and creates
// an S3 client with optional custom endpoint and path style settings.
//
// Parameters:
//   - ctx: Context for configuration loading and potential cancellation
//   - cfg: S3Config containing region, endpoint, and path style preferences
//
// Returns:
//   - *S3Store: A new S3Store instance with configured client and presigner
//   - error: Any error encountered during AWS config loading or client creation
//
// The function supports both standard AWS S3 endpoints and custom S3-compatible
// endpoints. When a custom endpoint is provided, it configures the client accordingly.
// The UsePathStyle setting controls whether to use path-style or virtual-hosted-style
// bucket addressing.
func NewS3Store(ctx context.Context, cfg config.S3Config) (*S3Store, error) {
	lo, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))

	if err != nil {
		return nil, err
	}

	opts := []func(*s3.Options){}
	if strings.TrimSpace(cfg.Endpoint) != "" {
		opts = append(opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = cfg.UsePathStyle
		})
	} else {
		opts = append(opts, func(o *s3.Options) {
			o.UsePathStyle = cfg.UsePathStyle
		})
	}

	c := s3.NewFromConfig(lo, opts...)
	return &S3Store{
		cfg:       cfg,
		client:    c,
		presigner: s3.NewPresignClient(c),
	}, nil
}

// HealthCheck verifies the S3 store connection by attempting to retrieve metadata
// for the configured bucket. Returns an error if the bucket is inaccessible or
// if there are connectivity issues with the S3 service.
func (s *S3Store) HealthCheck(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(s.cfg.Bucket),
	})
	return err
}

// PresignPut generates a presigned URL for uploading an object to S3.
// It creates a PUT request URL that allows clients to upload files directly to S3
// without requiring AWS credentials on the client side.
//
// The generated URL will have private ACL and AES-256 server-side encryption enabled.
//
// Parameters:
//   - ctx: Context for the operation
//   - p: PresignPutParams containing bucket, key, content type, and expiration duration
//
// Returns:
//   - string: The presigned URL for uploading
//   - error: An error if the operation fails or if expiresIn is <= 0
//
// Example:
//
//	url, err := s3Store.PresignPut(ctx, PresignPutParams{
//	    Bucket: "my-bucket",
//	    Key: "uploads/file.jpg",
//	    ContentType: "image/jpeg",
//	    ExpiresIn: time.Hour,
//	})
func (s *S3Store) PresignPut(ctx context.Context, p PresignPutParams) (string, error) {
	if p.ExpiresIn <= 0 {
		return "", errors.New("expiresIn must be greater than zero")
	}

	in := &s3.PutObjectInput{
		Bucket:               aws.String(p.Bucket),
		Key:                  aws.String(p.Key),
		ContentType:          aws.String(p.ContentType),
		ACL:                  types.ObjectCannedACLPrivate,
		ServerSideEncryption: types.ServerSideEncryptionAes256,
	}

	out, err := s.presigner.PresignPutObject(ctx, in, func(po *s3.PresignOptions) {
		po.Expires = p.ExpiresIn
	})

	if err != nil {
		return "", err
	}

	return out.URL, nil
}

// PresignGet generates a presigned URL for downloading an object from S3.
// The presigned URL allows temporary access to the specified object without requiring
// AWS credentials. The URL expires after the duration specified in ExpiresIn.
//
// Parameters:
//   - ctx: Context for the request, used for cancellation and timeouts
//   - p: PresignGetParams containing the bucket name, object key, and expiration duration
//
// Returns:
//   - string: The presigned URL that can be used to download the object
//   - error: An error if the operation fails or if ExpiresIn is not greater than zero
//
// The function validates that ExpiresIn is greater than zero before generating the URL.
// If the AWS S3 presigning operation fails, the underlying error is returned.
func (s *S3Store) PresignGet(ctx context.Context, p PresignGetParams) (string, error) {
	if p.ExpiresIn <= 0 {
		return "", errors.New("expiresIn must be greater than zero")
	}

	in := &s3.GetObjectInput{
		Bucket: aws.String(p.Bucket),
		Key:    aws.String(p.Key),
	}

	out, err := s.presigner.PresignGetObject(ctx, in, func(po *s3.PresignOptions) {
		po.Expires = p.ExpiresIn
	})

	if err != nil {
		return "", err
	}

	return out.URL, nil
}

// HeadObject retrieves metadata information about an object in the specified S3 bucket
// without returning the object data itself. It returns the object's ETag, size in bytes,
// and content type.
//
// Parameters:
//   - ctx: Context for the request, used for cancellation and timeouts
//   - bucket: The name of the S3 bucket containing the object
//   - key: The key (path) of the object within the bucket
//
// Returns:
//   - HeadObjectResult: Contains the object's metadata (ETag, size, content type)
//   - error: Any error that occurred during the operation, or nil on success
//
// This method is useful for checking if an object exists and getting its properties
// without downloading the actual content, making it efficient for validation and
// metadata retrieval operations.
func (s *S3Store) HeadObject(ctx context.Context, bucket, key string) (HeadObjectResult, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})

	if err != nil {
		return HeadObjectResult{}, err
	}

	res := HeadObjectResult{
		ETag:        aws.ToString(out.ETag),
		SizeBytes:   aws.ToInt64(out.ContentLength),
		ContentType: aws.ToString(out.ContentType),
	}

	return res, nil
}
