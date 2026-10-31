// Package sessions holds the one session write that spans modules: signing a user out
// everywhere. It is a bulk update, which the generic repository does not express.
package sessions

import (
	"context"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/session"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RevokeAll revokes a user's live sessions, except keep (uuid.Nil keeps none). It also
// revokes "login as" sessions the user started, so an admin who is demoted or signed out
// cannot keep acting through one. Inside store.WithTx it joins that transaction.
func RevokeAll(ctx context.Context, db *gorm.DB, userID uint, keep uuid.UUID) (int64, error) {
	conn := db
	if tx, ok := store.TxFromContext(ctx); ok {
		conn = tx
	}
	res := conn.WithContext(ctx).
		Model(&session.Session{}).
		Where("(user_id = ? OR impersonator_user_id = ?) AND revoked_at IS NULL AND uuid <> ?", userID, userID, keep).
		Update("revoked_at", time.Now().UTC())
	return res.RowsAffected, res.Error
}
