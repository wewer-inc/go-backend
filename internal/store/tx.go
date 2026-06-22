package store

import (
	"context"

	"gorm.io/gorm"
)

type txKey struct{}

// WithTx runs fn inside a database transaction. The transaction handle is also
// placed into the context passed to fn, so repository calls made with that
// context automatically join the same transaction (see TxFromContext). If fn
// returns an error, the transaction is rolled back.
func WithTx(ctx context.Context, db *gorm.DB, fn func(ctx context.Context, tx *gorm.DB) error) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		txCtx := context.WithValue(ctx, txKey{}, tx)
		return fn(txCtx, tx)
	})
}

// TxFromContext returns the transaction stored in ctx by WithTx, if any.
// Repositories use this to participate in an in-flight transaction instead of
// issuing writes on the root connection.
func TxFromContext(ctx context.Context) (*gorm.DB, bool) {
	tx, ok := ctx.Value(txKey{}).(*gorm.DB)
	return tx, ok
}
