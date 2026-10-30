package repo

import (
	"context"
	"fmt"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Create inserts a new entity of type T into the database.
func (r *GormRepo[T]) Create(ctx context.Context, entity *T) error {
	if entity == nil {
		return nil
	}
	return r.conn(ctx).Create(entity).Error
}

// GetByID retrieves an record of type T by its primary key ID.
func (r *GormRepo[T]) GetByID(ctx context.Context, id uint) (*T, error) {
	var entity T

	if err := r.conn(ctx).First(&entity, id).Error; err != nil {
		return nil, err
	}
	return &entity, nil
}

// GetByUUID retrieves an record of type T by its UUID.
func (r *GormRepo[T]) GetByUUID(ctx context.Context, id uuid.UUID) (*T, error) {
	var entity T

	if err := r.conn(ctx).
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
	db := r.conn(ctx).Model(&zeroT)
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

	db := r.conn(ctx).Model(&zeroT)
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
		zeroT    T
	)

	// 1) the requested page
	dataDB := r.conn(ctx).Model(&zeroT)
	dataDB = applyQueryOptsBase(dataDB, opts)

	offset := (page - 1) * pageSize
	if err := dataDB.Offset(offset).Limit(pageSize).Find(&entities).Error; err != nil {
		return nil, store.PageInfo{}, err
	}

	// 2) the total. A short page must be the last one, so offset plus its length is already
	// the answer and the extra query is avoided. Run the count only when that sum can't be
	// trusted: rows may follow a full page, and an empty page beyond the first may lie past
	// the end of the results.
	total := int64(offset + len(entities))
	if len(entities) == pageSize || (len(entities) == 0 && offset > 0) {
		countDB := r.conn(ctx).Model(&zeroT)
		countDB = applyQueryOptsBase(countDB, opts)

		if err := countDB.Count(&total).Error; err != nil {
			return nil, store.PageInfo{}, err
		}
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
	db := r.conn(ctx).Model(&zeroT)
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
	return r.conn(ctx).Save(entity).Error
}

// UpdateColumnsByID updates specific columns for entity T by primary key ID without invoking hooks.
func (r *GormRepo[T]) UpdateColumnsByID(ctx context.Context, id uint, cols map[string]any) error {
	var zeroT T
	return r.conn(ctx).
		Model(&zeroT).
		Where("id = ?", id).
		UpdateColumns(cols).Error
}

// UpdateColumnsGuarded is a compare-and-set for state transitions that concurrent requests
// can race on. It writes cols to row id only if the guard conditions still hold and returns
// whether a row changed, so the request that lost gets false instead of replacing what the
// winner wrote.
//
// Each guard key is a column name, checked before use, and a nil guard value means IS NULL.
// Anything equality cannot say goes in where. Those Exprs are raw SQL and, like
// QueryOpts.Where, must never contain request input. They are parenthesised one by one,
// since an OR inside one would otherwise escape the surrounding AND and reach rows other
// than id.
func (r *GormRepo[T]) UpdateColumnsGuarded(ctx context.Context, id uint, guard map[string]any, where []store.Clause, cols map[string]any) (bool, error) {
	var zeroT T
	db := r.conn(ctx)
	q := db.Model(&zeroT).Where("id = ?", id)
	for col, val := range guard {
		if !validIdentifier(col) {
			return false, fmt.Errorf("invalid guard column %q", col)
		}
		if val == nil {
			q = q.Where(col + " IS NULL")
			continue
		}
		q = q.Where(col+" = ?", val)
	}
	for _, c := range where {
		q = q.Where(db.Session(&gorm.Session{NewDB: true}).Where(c.Expr, c.Args...))
	}
	result := q.UpdateColumns(cols)
	if result.Error != nil {
		return false, result.Error
	}
	return result.RowsAffected > 0, nil
}

// SoftDelete marks an entity of type T as deleted by its primary key ID.
func (r *GormRepo[T]) SoftDelete(ctx context.Context, id uint) error {
	var zeroT T
	return r.conn(ctx).Delete(&zeroT, id).Error
}

// HardDelete permanently removes an entity of type T from the database by its primary key ID.
func (r *GormRepo[T]) HardDelete(ctx context.Context, id uint) error {
	var zeroT T
	return r.conn(ctx).Unscoped().Delete(&zeroT, id).Error
}

// Upsert inserts or updates an entity of type T based on conflict keys.
func (r *GormRepo[T]) Upsert(ctx context.Context, entity *T, conflictKeys []string) error {
	if entity == nil {
		return nil
	}

	db := r.conn(ctx)

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
