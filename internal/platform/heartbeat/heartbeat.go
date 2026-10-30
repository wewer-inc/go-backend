// Package heartbeat logs a line on a fixed schedule as evidence that the process is
// running and its logging works. Point an alert at the line's absence: successful health
// probes are not logged, so nothing else tells a quiet healthy service from a dead one.
package heartbeat

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Interval is how often the line is written.
const Interval = 5 * time.Minute

// Message is the line's message, for a log-based alert to match exactly.
const Message = "heartbeat"

// Beater owns the goroutine that logs Message on a timer.
type Beater struct {
	logger zerolog.Logger
	every  time.Duration
	fields func(*zerolog.Event)

	stop     context.CancelFunc
	stopped  chan struct{}
	stopOnce sync.Once
}

// New returns a Beater that logs through log once per interval. Nothing runs until Start.
func New(log zerolog.Logger, interval time.Duration) *Beater {
	return &Beater{logger: log, every: interval}
}

// WithFields adds fields to every beat, such as the database pool's counters.
func (b *Beater) WithFields(f func(*zerolog.Event)) *Beater {
	b.fields = f
	return b
}

// Start launches the loop. The first line is written immediately rather than after one
// interval, so a process that has just come up is visible without delay.
func (b *Beater) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	b.stop = cancel
	b.stopped = make(chan struct{})
	go b.run(ctx)
}

func (b *Beater) run(ctx context.Context) {
	defer close(b.stopped)
	ticker := time.NewTicker(b.every)
	defer ticker.Stop()

	b.beat()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.beat()
		}
	}
}

func (b *Beater) beat() {
	line := b.logger.Info()
	if b.fields != nil {
		b.fields(line)
	}
	line.Msg(Message)
}

// Stop cancels the loop and blocks until it has exited. Repeat calls are harmless, as is
// calling it on a Beater that never started.
func (b *Beater) Stop() {
	b.stopOnce.Do(func() {
		if b.stop != nil {
			b.stop()
			<-b.stopped
		}
	})
}
