package worker

import (
	"context"
	"errors"
	"runtime/debug"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
)

// ErrQueueFull is returned by Enqueue when the queue has no capacity. Callers
// can decide whether to drop, retry, or surface an error to the user.
var ErrQueueFull = errors.New("worker: queue full")

// ErrStopped is returned by Enqueue after the worker has begun shutting down.
var ErrStopped = errors.New("worker: stopped")

var jobsDropped = promauto.NewCounter(prometheus.CounterOpts{
	Name: "worker_jobs_dropped_total",
	Help: "Number of jobs dropped because the worker queue was full.",
})

var jobsPanicked = promauto.NewCounter(prometheus.CounterOpts{
	Name: "worker_jobs_panicked_total",
	Help: "Number of jobs that panicked and were recovered.",
})

// Job is a unit of work executed asynchronously.
type Job func(ctx context.Context) error

// Worker manages a pool of goroutines that drain a job queue.
type Worker struct {
	queue       chan Job
	concurrency int
	log         zerolog.Logger
	wg          sync.WaitGroup

	mu     sync.Mutex // guards closed and serialises sends against close
	closed bool
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
					w.runJob(ctx, job)
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}

// runJob runs job and contains any panic. Left uncaught, a panic on one of the pool's
// goroutines would end the process, along with every request in flight, over one bad job.
func (w *Worker) runJob(ctx context.Context, job Job) {
	defer w.containPanic()
	if err := job(ctx); err != nil {
		w.log.Error().Err(err).Msg("worker: job failed")
	}
}

func (w *Worker) containPanic() {
	cause := recover()
	if cause == nil {
		return
	}
	jobsPanicked.Inc()
	w.log.Error().
		Interface("panic", cause).
		Bytes("stack", debug.Stack()).
		Msg("worker: job panicked")
}

// Enqueue submits a job. It is non-blocking; if the queue is full it returns
// ErrQueueFull, and once the worker is stopping it returns ErrStopped. The
// mutex serialises the send with Stop's close so a job can never be sent on a
// closed channel.
func (w *Worker) Enqueue(job Job) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return ErrStopped
	}

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
// pool drains, Stop returns ctx.Err() rather than blocking forever. Safe to
// call more than once.
func (w *Worker) Stop(ctx context.Context) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	close(w.queue)
	w.mu.Unlock()

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
