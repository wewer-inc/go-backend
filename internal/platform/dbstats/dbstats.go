// Package dbstats lets the HTTP logger show what share of a request's latency went to
// the database. The logger puts a Stats on the request context, and the GORM callbacks
// in platform/db add to it, since repositories hand that same context to GORM. A context
// with no Stats, as in background work, records nothing.
//
// Importing only the standard library keeps this package at the bottom of the graph,
// where the middleware and the database layer can both depend on it.
package dbstats

import (
	"context"
	"sync/atomic"
	"time"
)

type statsKey struct{}

// Stats totals the queries run for a single request and the time they took. Its counters
// are atomic because one handler may run queries concurrently. A nil *Stats records
// nothing and reads as zero, so callers need no check.
type Stats struct {
	count atomic.Int64
	nanos atomic.Int64
}

// NewContext attaches an empty Stats to ctx and also returns it, so that the caller can
// read the totals after the handlers have run.
func NewContext(ctx context.Context) (context.Context, *Stats) {
	stats := new(Stats)
	return context.WithValue(ctx, statsKey{}, stats), stats
}

// FromContext returns the Stats attached to ctx. With none attached it returns a nil
// *Stats, which is still safe to use.
func FromContext(ctx context.Context) *Stats {
	stats, _ := ctx.Value(statsKey{}).(*Stats)
	return stats
}

// Record counts one query that took d.
func (s *Stats) Record(d time.Duration) {
	if s != nil {
		s.count.Add(1)
		s.nanos.Add(d.Nanoseconds())
	}
}

// Snapshot reads the queries counted so far and the time they add up to.
func (s *Stats) Snapshot() (queries int, total time.Duration) {
	if s != nil {
		queries, total = int(s.count.Load()), time.Duration(s.nanos.Load())
	}
	return queries, total
}
