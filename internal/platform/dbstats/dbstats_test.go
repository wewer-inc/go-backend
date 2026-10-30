package dbstats

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRecordAndSnapshot(t *testing.T) {
	ctx, s := NewContext(context.Background())
	if FromContext(ctx) != s {
		t.Fatal("FromContext must return the seeded Stats")
	}

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() { s.Record(time.Millisecond) })
	}
	wg.Wait()

	q, total := s.Snapshot()
	if q != 50 || total != 50*time.Millisecond {
		t.Fatalf("q=%d total=%s", q, total)
	}
}

func TestNilStatsIsANoOp(t *testing.T) {
	s := FromContext(context.Background())
	s.Record(time.Second)
	if q, total := s.Snapshot(); q != 0 || total != 0 {
		t.Fatalf("q=%d total=%s", q, total)
	}
}
