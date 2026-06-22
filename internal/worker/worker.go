package worker

import (
	"context"
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
)

// ErrQueueFull is returned by Enqueue when the queue has no capacity. Callers
// can decide whether to drop, retry, or surface an error to the user.
var ErrQueueFull = errors.New("worker: queue full")

var jobsDropped = promauto.NewCounter(prometheus.CounterOpts{
	Name: "worker_jobs_dropped_total",
	Help: "Number of jobs dropped because the worker queue was full.",
})

// Job is a unit of work executed asynchronously.
type Job func(ctx context.Context) error

// Worker manages a pool of goroutines that drain a job queue.
type Worker struct {
	queue       chan Job
	concurrency int
	log         zerolog.Logger
	wg          sync.WaitGroup
}

// New creates a Worker with the given concurrency and queue capacity.
func New(concurrency, queueSize int, log zerolog.Logger) *Worker {
	return &Worker{
		queue:       make(chan Job, queueSize),
		concurrency: concurrency,
		log:         log,
	}
}

// Start launches the goroutine pool. Jobs receive the provided context, so
// passing an app-scoped (cancelable) context lets in-flight jobs observe
// shutdown. The pool runs until the queue is closed (see Stop) or ctx is done.
func (w *Worker) Start(ctx context.Context) {
	for i := 0; i < w.concurrency; i++ {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			for {
				select {
				case job, ok := <-w.queue:
					if !ok {
						return
					}
					if err := job(ctx); err != nil {
						w.log.Error().Err(err).Msg("worker: job failed")
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}

// Enqueue submits a job. It is non-blocking; if the queue is full it returns
// ErrQueueFull (and records the drop) rather than blocking the caller.
func (w *Worker) Enqueue(job Job) error {
	select {
	case w.queue <- job:
		return nil
	default:
		jobsDropped.Inc()
		w.log.Warn().Msg("worker: queue full, dropping job")
		return ErrQueueFull
	}
}

// Stop stops accepting new jobs and waits for in-flight jobs to finish, bounded
// by ctx. If ctx is cancelled (e.g. the shutdown deadline elapses) before the
// pool drains, Stop returns ctx.Err() rather than blocking forever.
func (w *Worker) Stop(ctx context.Context) error {
	close(w.queue)

	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
