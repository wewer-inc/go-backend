//go:build integration

package auditlog

import (
	"context"
	"sync"
	"testing"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/pgtest"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/rs/zerolog"
	"gorm.io/gorm"
)

// Several recorders stand in for several instances: no mutex is shared, so only the
// advisory lock can keep the chain a single line.
func TestAdvisoryLockSerializesAcrossRecorders(t *testing.T) {
	db := pgtest.Open(t)
	if err := db.AutoMigrate(&audit.Log{}); err != nil {
		t.Fatal(err)
	}

	const instances, appends = 6, 25
	var wg sync.WaitGroup
	for i := 0; i < instances; i++ {
		rec := NewGormRecorder(db, zerolog.Nop())
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < appends; j++ {
				if err := rec.Record(context.Background(), Entry{Event: "login.success", Detail: map[string]any{"i": j}}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()

	res, err := VerifyStored(context.Background(), db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Checked != instances*appends {
		t.Fatalf("chain forked: %+v", res)
	}
}

func TestChainVerifiesAfterAPostgresRoundTrip(t *testing.T) {
	db := pgtest.Open(t)
	if err := db.AutoMigrate(&audit.Log{}); err != nil {
		t.Fatal(err)
	}
	rec := NewGormRecorder(db, zerolog.Nop())
	actor := uint(9)
	ctx := ContextWithImpersonator(context.Background(), 4)
	if err := rec.Record(ctx, Entry{Event: "a", ActorUserID: &actor, IP: "10.0.0.1", Detail: map[string]any{"z": 1, "a": "x"}}); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyStored(context.Background(), db, nil)
	if err != nil || !res.OK {
		t.Fatalf("%+v %v", res, err)
	}
	if err := db.Exec(`UPDATE audit_logs SET ip = '10.0.0.2'`).Error; err != nil {
		t.Fatal(err)
	}
	if res, _ := VerifyStored(context.Background(), db, nil); res.OK {
		t.Fatal("an edit went unnoticed")
	}
}

func TestCheckpointDetectsTailTruncationOnPostgres(t *testing.T) {
	db := pgtest.Open(t)
	if err := db.AutoMigrate(&audit.Log{}); err != nil {
		t.Fatal(err)
	}
	rec := NewGormRecorder(db, zerolog.Nop())
	for i := 0; i < 3; i++ {
		if err := rec.Record(context.Background(), Entry{Event: "a"}); err != nil {
			t.Fatal(err)
		}
	}
	head, err := VerifyStored(context.Background(), db, nil)
	if err != nil || !head.OK {
		t.Fatalf("%+v %v", head, err)
	}
	cp := Checkpoint{ID: head.HeadID, Hash: head.Head}
	if res, err := VerifyStored(context.Background(), db, &cp); err != nil || !res.OK || !res.CheckpointVerified {
		t.Fatalf("%+v %v", res, err)
	}
	if err := db.Exec(`DELETE FROM audit_logs WHERE id = ?`, cp.ID).Error; err != nil {
		t.Fatal(err)
	}
	if res, err := VerifyStored(context.Background(), db, &cp); err != nil || res.OK || res.Reason != ReasonCheckpointMissing {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestRollbackReleasesTheLockAndLeavesNoRow(t *testing.T) {
	db := pgtest.Open(t)
	if err := db.AutoMigrate(&audit.Log{}); err != nil {
		t.Fatal(err)
	}
	rec := NewGormRecorder(db, zerolog.Nop())
	_ = store.WithTx(context.Background(), db, func(ctx context.Context, _ *gorm.DB) error {
		if err := rec.Record(ctx, Entry{Event: "rolled back"}); err != nil {
			t.Fatal(err)
		}
		return gorm.ErrInvalidTransaction
	})
	if err := rec.Record(context.Background(), Entry{Event: "after"}); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyStored(context.Background(), db, nil)
	if err != nil || !res.OK || res.Checked != 1 {
		t.Fatalf("%+v %v", res, err)
	}
}
