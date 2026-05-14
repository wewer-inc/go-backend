package store

import (
	"context"

	"gorm.io/gorm"
)

// WithTx runs fn inside a database transaction.
// If fn returns an error, the transaction is rolled back.
func WithTx(ctx context.Context, db *gorm.DB, fn func(ctx context.Context, tx *gorm.DB) error) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {

		// We pass the same ctx down to the function. This allows the function
		// to use the same context for logging, deadlines, etc. Can be extended
		// later if needed.
		return fn(ctx, tx)
	})
}
