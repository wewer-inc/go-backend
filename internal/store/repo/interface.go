package repo

import (
	"context"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Repo is a generic repository contract for an entity T
type Repo[T any] interface {
	Create(ctx context.Context, entity *T) error
	GetByID(ctx context.Context, id uint) (*T, error)
	GetByUUID(ctx context.Context, uuid uuid.UUID) (*T, error)
	// GetOne returns the first record matching opts, or gorm.ErrRecordNotFound.
	GetOne(ctx context.Context, opts store.QueryOpts) (*T, error)
	Exists(ctx context.Context, opts store.QueryOpts) (bool, error)
	List(ctx context.Context, opts store.QueryOpts) ([]T, store.PageInfo, error)
	Count(ctx context.Context, opts store.QueryOpts) (int64, error)
	Update(ctx context.Context, entity *T) error
	UpdateColumnsByID(ctx context.Context, id uint, cols map[string]any) error
	SoftDelete(ctx context.Context, id uint) error
	HardDelete(ctx context.Context, id uint) error
	Upsert(ctx context.Context, entity *T, conflictKeys []string) error
}

// GormRepo is a concrete implementation of Repo[T] backed by *gorm.DB.
type GormRepo[T any] struct {
	db *gorm.DB
}

// NewGormRepo constructs a new GormRepo for type T.
func NewGormRepo[T any](db *gorm.DB) Repo[T] {
	return &GormRepo[T]{db: db}
}
