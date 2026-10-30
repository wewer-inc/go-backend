package worker

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestPanickingJobDoesNotKillThePool(t *testing.T) {
	w := New(1, 4, zerolog.Nop())
	w.Start(context.Background())

	var ran atomic.Bool
	if err := w.Enqueue(func(context.Context) error { panic("boom") }); err != nil {
		t.Fatal(err)
	}
	if err := w.Enqueue(func(context.Context) error { ran.Store(true); return nil }); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !ran.Load() {
		t.Fatal("the job after the panic never ran")
	}
}

func TestEnqueueAfterStopIsRefused(t *testing.T) {
	w := New(1, 1, zerolog.Nop())
	w.Start(context.Background())
	if err := w.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := w.Enqueue(func(context.Context) error { return nil }); !errors.Is(err, ErrStopped) {
		t.Fatalf("err = %v", err)
	}
}

func TestEnqueueOnFullQueueIsRefused(t *testing.T) {
	w := New(1, 1, zerolog.Nop())
	if err := w.Enqueue(func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := w.Enqueue(func(context.Context) error { return nil }); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("err = %v", err)
	}
}
