package auditlog

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/entities/audit"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
	"github.com/rs/zerolog"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func newDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	// One connection: each new one to file::memory: would be a different empty database.
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&audit.Log{}); err != nil {
		t.Fatal(err)
	}
	return db
}

func rowsOf(t *testing.T, db *gorm.DB) []audit.Log {
	t.Helper()
	var rows []audit.Log
	if err := db.Order("id ASC").Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func stubbedPG(db *gorm.DB) *Recorder {
	return &Recorder{appender: &pgAppender{db: db, lock: func(*gorm.DB) error { return nil }}, log: zerolog.Nop()}
}

func TestChainLinksAndVerifies(t *testing.T) {
	db := newDB(t)
	rec := NewRecorder(repo.NewGormRepo[audit.Log](db), zerolog.Nop())
	actor := uint(7)
	for _, ev := range []string{"a", "b", "c"} {
		if err := rec.Record(context.Background(), Entry{Event: ev, ActorUserID: &actor, IP: "10.0.0.1"}); err != nil {
			t.Fatal(err)
		}
	}
	rows := rowsOf(t, db)
	if len(rows) != 3 || rows[0].PrevHash != "" || rows[1].PrevHash != rows[0].Hash || rows[2].PrevHash != rows[1].Hash {
		t.Fatalf("not a chain: %+v", rows)
	}
	if id, ok := VerifyChain(rows); !ok {
		t.Fatalf("does not verify at %d", id)
	}
}

// Every field the hash is meant to cover must change it.
func TestVerificationCatchesTampering(t *testing.T) {
	seed := func(t *testing.T) []audit.Log {
		db := newDB(t)
		rec := NewRecorder(repo.NewGormRepo[audit.Log](db), zerolog.Nop())
		actor, imp := uint(1), uint(2)
		for i := 0; i < 3; i++ {
			if err := rec.Record(context.Background(), Entry{
				Event: "e", ActorUserID: &actor, ImpersonatorUserID: &imp, IP: "1.1.1.1", Detail: map[string]any{"k": i},
			}); err != nil {
				t.Fatal(err)
			}
		}
		return rowsOf(t, db)
	}
	other := uint(99)
	edits := map[string]func(r []audit.Log) []audit.Log{
		"event":        func(r []audit.Log) []audit.Log { r[1].Event = "x"; return r },
		"actor":        func(r []audit.Log) []audit.Log { r[1].ActorUserID = &other; return r },
		"impersonator": func(r []audit.Log) []audit.Log { r[1].ImpersonatorUserID = nil; return r },
		"ip":           func(r []audit.Log) []audit.Log { r[1].IP = "2.2.2.2"; return r },
		"detail":       func(r []audit.Log) []audit.Log { r[1].Detail = `{"k":42}`; return r },
		"created_at":   func(r []audit.Log) []audit.Log { r[1].CreatedAt = r[1].CreatedAt.Add(time.Second); return r },
		"version":      func(r []audit.Log) []audit.Log { r[1].ChainVersion = 2; return r },
		"deleted row":  func(r []audit.Log) []audit.Log { return append(r[:1], r[2:]...) },
		"reordered":    func(r []audit.Log) []audit.Log { r[1], r[2] = r[2], r[1]; return r },
	}
	for name, edit := range edits {
		t.Run(name, func(t *testing.T) {
			if _, ok := VerifyChain(edit(seed(t))); ok {
				t.Fatal("tampering went unnoticed")
			}
		})
	}
}

// A pipe-joined hash input would let bytes move between fields unnoticed.
func TestHashSeparatesFields(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	a := &audit.Log{CreatedAt: at, Event: "a|b", IP: ""}
	b := &audit.Log{CreatedAt: at, Event: "a", IP: "b"}
	if RecomputeHash(a) == RecomputeHash(b) {
		t.Fatal("hash does not separate fields")
	}
}

func TestHashSurvivesATimezoneOnRead(t *testing.T) {
	at := time.Unix(1700000000, 123000).UTC()
	a := &audit.Log{CreatedAt: at, Event: "a"}
	b := &audit.Log{CreatedAt: at.In(time.FixedZone("x", 3600)), Event: "a"}
	if RecomputeHash(a) != RecomputeHash(b) {
		t.Fatal("the same instant must hash the same whatever zone the driver returns")
	}
}

func TestCreatedAtFitsPostgresPrecision(t *testing.T) {
	db := newDB(t)
	rec := NewRecorder(repo.NewGormRepo[audit.Log](db), zerolog.Nop())
	if err := rec.Record(context.Background(), Entry{Event: "a"}); err != nil {
		t.Fatal(err)
	}
	if ns := rowsOf(t, db)[0].CreatedAt.Nanosecond(); ns%1000 != 0 {
		t.Fatalf("sub-microsecond timestamp %d would not survive a Postgres round trip", ns)
	}
}

func TestImpersonatorComesFromContextUnlessExplicit(t *testing.T) {
	db := newDB(t)
	rec := NewRecorder(repo.NewGormRepo[audit.Log](db), zerolog.Nop())
	ctx := ContextWithImpersonator(context.Background(), 5)
	explicit := uint(6)
	for _, e := range []Entry{{Event: "ctx"}, {Event: "explicit", ImpersonatorUserID: &explicit}} {
		if err := rec.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := rec.Record(context.Background(), Entry{Event: "none"}); err != nil {
		t.Fatal(err)
	}
	rows := rowsOf(t, db)
	if rows[0].ImpersonatorUserID == nil || *rows[0].ImpersonatorUserID != 5 {
		t.Errorf("context value not applied: %+v", rows[0].ImpersonatorUserID)
	}
	if rows[1].ImpersonatorUserID == nil || *rows[1].ImpersonatorUserID != 6 {
		t.Errorf("explicit value lost: %+v", rows[1].ImpersonatorUserID)
	}
	if rows[2].ImpersonatorUserID != nil {
		t.Errorf("no impersonator expected: %+v", rows[2].ImpersonatorUserID)
	}
	if ctx := ContextWithImpersonator(context.Background(), 0); impersonatorFrom(ctx) != nil {
		t.Error("a zero id must not count as an impersonator")
	}
	if id, ok := VerifyChain(rows); !ok {
		t.Errorf("does not verify at %d", id)
	}
}

type detailStruct struct {
	Name  string `json:"name"`
	Token string `json:"token"`
}

func TestSensitiveDetailIsRedactedWhereverItSits(t *testing.T) {
	db := newDB(t)
	rec := NewRecorder(repo.NewGormRepo[audit.Log](db), zerolog.Nop())
	err := rec.Record(context.Background(), Entry{Event: "a", Detail: map[string]any{
		"new_password":  "secret-value-01",
		"refresh_token": "secret-value-02",
		"totp_secret":   "secret-value-03",
		"nested":        map[string]any{"Backup_Code": "secret-value-04"},
		"in_a_slice":    []any{map[string]any{"password": "secret-value-05"}},
		"typed_slice":   []map[string]string{{"apiKey": "secret-value-06"}},
		"typed_map":     map[string]string{"api-key": "secret-value-07"},
		"a_struct":      detailStruct{Name: "keep-me-too", Token: "secret-value-08"},
		"backupCode":    "secret-value-09",
		"session":       "keep-me",
		"count":         3,
		"big_id":        uint64(18446744073709551615),
	}})
	if err != nil {
		t.Fatal(err)
	}
	detail := rowsOf(t, db)[0].Detail
	if strings.Contains(detail, "secret-value") {
		t.Errorf("a secret reached the chain: %s", detail)
	}
	for _, kept := range []string{"keep-me", "keep-me-too", `"count":3`, "18446744073709551615"} {
		if !strings.Contains(detail, kept) {
			t.Errorf("ordinary value %q lost: %s", kept, detail)
		}
	}
}

func TestSensitiveKeyMatching(t *testing.T) {
	sensitive := []string{
		"password", "newPassword", "PASSWD", "pwd", "user_pwd", "client-secret", "accessToken", "totp",
		"otp", "OTP", "otp_code", "otpCode", "OTPCode", "userOTP", "sms-otp", "backup_code", "backup-code",
		"backupCode", "recovery_codes", "apiKey", "api_key", "api-key", "API_KEY", "Authorization",
		"set-cookie", "credentials",
	}
	for _, k := range sensitive {
		if !isSensitiveKey(k) {
			t.Errorf("%q should be redacted", k)
		}
	}
	ordinary := []string{"hotpot", "HotPot", "hot_pot", "session", "method", "old_role", "new_role", "expires_at", "count", "scope"}
	for _, k := range ordinary {
		if isSensitiveKey(k) {
			t.Errorf("%q should not be redacted", k)
		}
	}
}

// A value that cannot be marshalled must not be stored some other way, and must not cost
// the event or its other details.
func TestUnencodableDetailValueIsDropped(t *testing.T) {
	db := newDB(t)
	rec := NewRecorder(repo.NewGormRepo[audit.Log](db), zerolog.Nop())
	err := rec.Record(context.Background(), Entry{Event: "a", Detail: map[string]any{
		"bad":     make(chan int),
		"nested":  map[string]any{"fn": func() {}},
		"session": "keep-me",
	}})
	if err != nil {
		t.Fatal(err)
	}
	rows := rowsOf(t, db)
	if len(rows) != 1 {
		t.Fatalf("%d rows", len(rows))
	}
	for _, want := range []string{`"bad":"[unencodable]"`, `"nested":"[unencodable]"`, `"session":"keep-me"`} {
		if !strings.Contains(rows[0].Detail, want) {
			t.Errorf("missing %s in %s", want, rows[0].Detail)
		}
	}
	if id, ok := VerifyChain(rows); !ok {
		t.Errorf("does not verify at %d", id)
	}
}

func TestLogLineCarriesIDsNotDetail(t *testing.T) {
	db := newDB(t)
	var buf bytes.Buffer
	rec := NewRecorder(repo.NewGormRepo[audit.Log](db), zerolog.New(&buf))
	actor := uint(3)
	if err := rec.Record(context.Background(), Entry{Event: "a", ActorUserID: &actor, Detail: map[string]any{"target": "private"}}); err != nil {
		t.Fatal(err)
	}
	if s := buf.String(); !strings.Contains(s, `"actor_user_id":3`) || strings.Contains(s, "private") {
		t.Fatalf("log line: %s", s)
	}
}

func TestConcurrentRecordsOnTheMutexRecorderFormOneChain(t *testing.T) {
	db := newDB(t)
	rec := NewRecorder(repo.NewGormRepo[audit.Log](db), zerolog.Nop())
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := rec.Record(context.Background(), Entry{Event: "a"}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	rows := rowsOf(t, db)
	if len(rows) != 20 {
		t.Fatalf("%d rows", len(rows))
	}
	if id, ok := VerifyChain(rows); !ok {
		t.Fatalf("does not verify at %d", id)
	}
}

type failingRepo struct{ repo.Repo[audit.Log] }

func (failingRepo) GetOne(context.Context, store.QueryOpts) (*audit.Log, error) {
	return nil, errors.New("database unavailable")
}

func (failingRepo) Create(context.Context, *audit.Log) error {
	panic("must not write when the head could not be read")
}

func TestUnreadableHeadDoesNotStartASecondRoot(t *testing.T) {
	rec := NewRecorder(failingRepo{}, zerolog.Nop())
	if err := rec.Record(context.Background(), Entry{Event: "a"}); err == nil {
		t.Fatal("expected the read failure to surface")
	}
}

func TestLockedTransactionAppendsVerifyAsOneChain(t *testing.T) {
	db := newDB(t)
	rec := stubbedPG(db)
	for _, ev := range []string{"a", "b", "c"} {
		if err := rec.Record(context.Background(), Entry{Event: ev}); err != nil {
			t.Fatal(err)
		}
	}
	if id, ok := VerifyChain(rowsOf(t, db)); !ok {
		t.Fatalf("does not verify at %d", id)
	}
}

// The test database is sqlite, where the advisory lock function does not exist. An error
// therefore shows the real statement ran, and the empty table shows a failed lock writes
// nothing.
func TestProductionRecorderFailsClosedWithoutTheLock(t *testing.T) {
	db := newDB(t)
	rec := NewGormRecorder(db, zerolog.Nop())
	if err := rec.Record(context.Background(), Entry{Event: "a"}); err == nil {
		t.Fatal("append must fail when the chain lock cannot be taken")
	}
	if rows := rowsOf(t, db); len(rows) != 0 {
		t.Fatalf("wrote %d rows without the lock", len(rows))
	}
}

func TestRecordJoinsTheCallersTransaction(t *testing.T) {
	db := newDB(t)
	rec := stubbedPG(db)
	boom := errors.New("boom")
	err := store.WithTx(context.Background(), db, func(ctx context.Context, _ *gorm.DB) error {
		if err := rec.Record(ctx, Entry{Event: "rolled back"}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if rows := rowsOf(t, db); len(rows) != 0 {
		t.Fatal("a rolled-back change left its audit row behind")
	}
}

func TestRecordSurvivesACancelledRequest(t *testing.T) {
	db := newDB(t)
	rec := stubbedPG(db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rec.Record(ctx, Entry{Event: "a"}); err != nil {
		t.Fatal(err)
	}
	if len(rowsOf(t, db)) != 1 {
		t.Fatal("a dropped connection erased the record")
	}
}

func TestVerifyStoredWalksAndFindsTheBadRow(t *testing.T) {
	db := newDB(t)
	rec := stubbedPG(db)
	for i := 0; i < 5; i++ {
		if err := rec.Record(context.Background(), Entry{Event: "a"}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := VerifyStored(context.Background(), db, nil)
	if err != nil || !res.OK || res.Checked != 5 || res.Head == "" || res.HeadID != 5 || res.CheckpointVerified {
		t.Fatalf("clean chain: %+v %v", res, err)
	}
	if err := db.Exec(`UPDATE audit_logs SET event = 'edited' WHERE id = 3`).Error; err != nil {
		t.Fatal(err)
	}
	res, err = VerifyStored(context.Background(), db, nil)
	if err != nil || res.OK || res.FirstBadID != 3 || res.Reason != ReasonChainBroken {
		t.Fatalf("tampered chain: %+v %v", res, err)
	}
}

func TestCheckpointDetectsTailTruncation(t *testing.T) {
	seed := func(t *testing.T) (*gorm.DB, Checkpoint) {
		db := newDB(t)
		rec := stubbedPG(db)
		for i := 0; i < 5; i++ {
			if err := rec.Record(context.Background(), Entry{Event: "a"}); err != nil {
				t.Fatal(err)
			}
		}
		res, err := VerifyStored(context.Background(), db, nil)
		if err != nil || !res.OK {
			t.Fatalf("%+v %v", res, err)
		}
		return db, Checkpoint{ID: res.HeadID, Hash: res.Head}
	}

	t.Run("an intact chain passes and says so", func(t *testing.T) {
		db, cp := seed(t)
		res, err := VerifyStored(context.Background(), db, &cp)
		if err != nil || !res.OK || !res.CheckpointVerified {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("rows after the checkpoint may follow it", func(t *testing.T) {
		db, cp := seed(t)
		if err := stubbedPG(db).Record(context.Background(), Entry{Event: "later"}); err != nil {
			t.Fatal(err)
		}
		res, err := VerifyStored(context.Background(), db, &cp)
		if err != nil || !res.OK || !res.CheckpointVerified || res.Checked != 6 {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("deleted tail", func(t *testing.T) {
		db, cp := seed(t)
		if err := db.Exec(`DELETE FROM audit_logs WHERE id >= 4`).Error; err != nil {
			t.Fatal(err)
		}
		// Without the checkpoint this is indistinguishable from a shorter honest chain.
		if res, err := VerifyStored(context.Background(), db, nil); err != nil || !res.OK || res.CheckpointVerified {
			t.Fatalf("no checkpoint: %+v %v", res, err)
		}
		res, err := VerifyStored(context.Background(), db, &cp)
		if err != nil || res.OK || res.Reason != ReasonCheckpointMissing {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("emptied table", func(t *testing.T) {
		db, cp := seed(t)
		if err := db.Exec(`DELETE FROM audit_logs`).Error; err != nil {
			t.Fatal(err)
		}
		res, err := VerifyStored(context.Background(), db, &cp)
		if err != nil || res.OK || res.Reason != ReasonCheckpointMissing {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("rewritten chain with valid hashes", func(t *testing.T) {
		db, cp := seed(t)
		rows := rowsOf(t, db)
		if err := db.Exec(`DELETE FROM audit_logs`).Error; err != nil {
			t.Fatal(err)
		}
		prev := ""
		for i := range rows {
			rows[i].Event = "rewritten"
			rows[i].PrevHash = prev
			rows[i].Hash = RecomputeHash(&rows[i])
			prev = rows[i].Hash
			if err := db.Create(&rows[i]).Error; err != nil {
				t.Fatal(err)
			}
		}
		res, err := VerifyStored(context.Background(), db, &cp)
		if err != nil || res.OK || res.Reason != ReasonCheckpointMismatch || res.FirstBadID != cp.ID {
			t.Fatalf("%+v %v", res, err)
		}
	})
	t.Run("a broken chain is reported before the checkpoint", func(t *testing.T) {
		db, cp := seed(t)
		if err := db.Exec(`UPDATE audit_logs SET event = 'edited' WHERE id = 2`).Error; err != nil {
			t.Fatal(err)
		}
		res, err := VerifyStored(context.Background(), db, &cp)
		if err != nil || res.OK || res.Reason != ReasonChainBroken || res.FirstBadID != 2 {
			t.Fatalf("%+v %v", res, err)
		}
	})
}
