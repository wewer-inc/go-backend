package db

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/platform/dbstats"
	"github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
	"github.com/rs/zerolog"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type logRow struct {
	ID    uint
	Email string `gorm:"uniqueIndex"`
}

func openLogged(t *testing.T, cfg Config) (*gorm.DB, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	gdb, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{Logger: newGormLogger(cfg, zerolog.New(&buf))})
	if err != nil {
		t.Fatal(err)
	}
	registerQueryTiming(gdb)
	if err := gdb.AutoMigrate(&logRow{}); err != nil {
		t.Fatal(err)
	}
	return gdb, &buf
}

func failInsert(ctx context.Context, gdb *gorm.DB) error {
	return gdb.WithContext(ctx).Create(&logRow{ID: 1, Email: "secret@example.com"}).Error
}

func TestSQLLogRedactsValuesByDefault(t *testing.T) {
	gdb, buf := openLogged(t, Config{SlowThreshold: time.Hour})
	ctx := context.Background()
	if err := failInsert(ctx, gdb); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := failInsert(ctx, gdb); err == nil {
		t.Fatal("the duplicate insert should fail")
	}
	if buf.Len() == 0 {
		t.Fatal("a failed statement must be logged")
	}
	if strings.Contains(buf.String(), "secret@example.com") {
		t.Fatalf("value reached the log: %s", buf.String())
	}
}

func TestSQLLogCanOptInToValues(t *testing.T) {
	gdb, buf := openLogged(t, Config{SlowThreshold: time.Hour, LogQueryValues: true})
	ctx := context.Background()
	_ = failInsert(ctx, gdb)
	buf.Reset()
	_ = failInsert(ctx, gdb)
	if !strings.Contains(buf.String(), "secret@example.com") {
		t.Fatalf("opted-in value missing: %s", buf.String())
	}
}

func TestSQLLogIsQuietAboutExpectedErrorsOnly(t *testing.T) {
	gdb, buf := openLogged(t, Config{SlowThreshold: time.Hour})
	_ = failInsert(context.Background(), gdb)
	buf.Reset()

	ctx := store.ExpectError(context.Background(), func(err error) bool { return err != nil })
	if err := failInsert(ctx, gdb); err == nil {
		t.Fatal("the error must still reach the caller")
	}
	if buf.Len() != 0 {
		t.Fatalf("expected error was logged: %s", buf.String())
	}

	other := errors.New("not this one")
	ctx = store.ExpectError(context.Background(), func(err error) bool { return errors.Is(err, other) })
	_ = failInsert(ctx, gdb)
	if buf.Len() == 0 {
		t.Fatal("an unmatched error must still be logged")
	}
}

func TestSQLLogNamesTheCallerNotTheWrapper(t *testing.T) {
	gdb, buf := openLogged(t, Config{SlowThreshold: time.Hour})
	_ = failInsert(context.Background(), gdb)
	buf.Reset()
	_ = failInsert(context.Background(), gdb)
	if strings.Contains(buf.String(), "sqllog") {
		t.Fatalf("log names the wrapper as the call site: %s", buf.String())
	}
}

func TestQueryTimingRecordsIntoTheRequestStats(t *testing.T) {
	gdb, _ := openLogged(t, Config{SlowThreshold: time.Hour})
	ctx, stats := dbstats.NewContext(context.Background())

	var rows []logRow
	if err := gdb.WithContext(ctx).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if err := gdb.WithContext(ctx).Create(&logRow{Email: "a@example.com"}).Error; err != nil {
		t.Fatal(err)
	}
	if q, _ := stats.Snapshot(); q != 2 {
		t.Fatalf("queries = %d", q)
	}
}

func TestPoolStatsFieldsWritesTheDict(t *testing.T) {
	gdb, _ := openLogged(t, Config{SlowThreshold: time.Hour})
	var buf bytes.Buffer
	log := zerolog.New(&buf)
	e := log.Info()
	PoolStatsFields(gdb)(e)
	e.Msg("x")
	if !strings.Contains(buf.String(), `"db_pool"`) {
		t.Fatalf("missing dict: %s", buf.String())
	}
	PoolStatsFields(nil)(log.Info())
}

func TestReadyCheckPassesUntilThePoolIsStopped(t *testing.T) {
	gdb, _ := openLogged(t, Config{SlowThreshold: time.Hour})
	ctx := context.Background()

	for _, timeout := range []time.Duration{time.Second, 0} {
		if err := ReadyCheck(ctx, gdb, timeout); err != nil {
			t.Fatalf("timeout %v: %v", timeout, err)
		}
	}
	if pool, err := SQLDB(gdb); err != nil || pool == nil {
		t.Fatalf("SQLDB = %v, %v", pool, err)
	}
	if err := Stop(gdb); err != nil {
		t.Fatal(err)
	}
	if err := ReadyCheck(ctx, gdb, time.Second); err == nil {
		t.Fatal("a stopped pool must not report ready")
	}
}
