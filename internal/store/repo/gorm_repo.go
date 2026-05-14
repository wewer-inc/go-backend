package repo

import (
	"context"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/google/uuid"
	"gorm.io/gorm/clause"
)

// Create inserts a new entity of type T into the database.
func (r *GormRepo[T]) Create(ctx context.Context, entity *T) error {
	if entity == nil {
		return nil
	}
	return r.db.WithContext(ctx).Create(entity).Error
}

// GetByID retrieves an record of type T by its primary key ID.
func (r *GormRepo[T]) GetByID(ctx context.Context, id uint) (*T, error) {
	var entity T

	if err := r.db.WithContext(ctx).First(&entity, id).Error; err != nil {
		return nil, err
	}
	return &entity, nil
}

// GetByUUID retrieves an record of type T by its UUID.
func (r *GormRepo[T]) GetByUUID(ctx context.Context, id uuid.UUID) (*T, error) {
	var entity T

	if err := r.db.WithContext(ctx).
		Where("uuid = ?", id).
		First(&entity).Error; err != nil {
		return nil, err
	}
	return &entity, nil
}

// GetOne returns the first record matching opts, or gorm.ErrRecordNotFound if none.
func (r *GormRepo[T]) GetOne(ctx context.Context, opts store.QueryOpts) (*T, error) {
	var (
		entity T
		zeroT  T
	)
	db := r.db.WithContext(ctx).Model(&zeroT)
	db = applyQueryOptsBase(db, opts)
	if err := db.First(&entity).Error; err != nil {
		return nil, err
	}
	return &entity, nil
}

// Exists checks if any record of type T exists that matches the provided QueryOpts. (Ignores pagination)
func (r *GormRepo[T]) Exists(ctx context.Context, opts store.QueryOpts) (bool, error) {
	var (
		one   int
		zeroT T
	)

	db := r.db.WithContext(ctx).Model(&zeroT)
	db = applyQueryOptsBase(db, opts)

	// Ignore pagination and fetch cheapest result
	db = db.Limit(1).Offset(0).Select("1")

	// Scan doesn't error on "no rows", so we can use it to check existence
	if err := db.Scan(&one).Error; err != nil {
		return false, err
	}

	return one == 1, nil
}

// List retrieves a list of entities of type T based on the provided QueryOpts
// along with pagination information.
func (r *GormRepo[T]) List(ctx context.Context, opts store.QueryOpts) ([]T, store.PageInfo, error) {
	page, pageSize := normalizePagination(opts)

	// base model for this entity type
	var (
		entities []T
		total    int64
		zeroT    T
	)

	// 1) count query (no pagination)
	countDB := r.db.WithContext(ctx).Model(&zeroT)
	countDB = applyQueryOptsBase(countDB, opts)

	if err := countDB.Count(&total).Error; err != nil {
		return nil, store.PageInfo{}, err
	}

	// 2) data query (with pagination)
	dataDB := r.db.WithContext(ctx).Model(&zeroT)
	dataDB = applyQueryOptsBase(dataDB, opts)

	offset := (page - 1) * pageSize
	dataDB = dataDB.Limit(pageSize).Offset(offset)

	if err := dataDB.Find(&entities).Error; err != nil {
		return nil, store.PageInfo{}, err
	}

	// 3) page info
	hasNext := int64(page*pageSize) < total

	pageInfo := store.PageInfo{
		Page:     page,
		PageSize: pageSize,
		Total:    total,
		HasNext:  hasNext,
	}

	return entities, pageInfo, nil
}

// Count returns the total number of records of type T that match the provided QueryOpts.(Ignores pagination)
func (r *GormRepo[T]) Count(ctx context.Context, opts store.QueryOpts) (int64, error) {
	var (
		total int64
		zeroT T
	)
	db := r.db.WithContext(ctx).Model(&zeroT)
	db = applyQueryOptsBase(db, opts)

	// Ignore pagination for count even if set in opts
	db = db.Limit(-1).Offset(-1)

	if err := db.Count(&total).Error; err != nil {
		return 0, err
	}
	return total, nil
}

// Update modifies an existing entity of type T in the database.
func (r *GormRepo[T]) Update(ctx context.Context, entity *T) error {
	if entity == nil {
		return nil
	}
	return r.db.WithContext(ctx).Save(entity).Error
}

// UpdateColumnsByID updates specific columns for entity T by primary key ID without invoking hooks.
func (r *GormRepo[T]) UpdateColumnsByID(ctx context.Context, id uint, cols map[string]any) error {
	var zeroT T
	return r.db.WithContext(ctx).
		Model(&zeroT).
		Where("id = ?", id).
		UpdateColumns(cols).Error
}

// SoftDelete marks an entity of type T as deleted by its primary key ID.
func (r *GormRepo[T]) SoftDelete(ctx context.Context, id uint) error {
	var zeroT T
	return r.db.WithContext(ctx).Delete(&zeroT, id).Error
}

// HardDelete permanently removes an entity of type T from the database by its primary key ID.
func (r *GormRepo[T]) HardDelete(ctx context.Context, id uint) error {
	var zeroT T
	return r.db.WithContext(ctx).Unscoped().Delete(&zeroT, id).Error
}

// Upsert inserts or updates an entity of type T based on conflict keys.
func (r *GormRepo[T]) Upsert(ctx context.Context, entity *T, conflictKeys []string) error {
	if entity == nil {
		return nil
	}

	db := r.db.WithContext(ctx)

	// No conflict keys -> simple save behavior
	if len(conflictKeys) == 0 {
		return db.Save(entity).Error
	}

	cols := make([]clause.Column, len(conflictKeys))
	for i, k := range conflictKeys {
		cols[i] = clause.Column{Name: k}
	}

	return db.Clauses(clause.OnConflict{
		Columns:   cols,
		UpdateAll: true, // Update all fields on conflict
	}).Create(entity).Error
}
