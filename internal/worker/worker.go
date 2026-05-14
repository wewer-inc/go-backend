package worker

import (
	"context"
	"sync"

	"github.com/rs/zerolog"
)

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

// Start launches the goroutine pool. The pool runs until ctx is cancelled and
// all in-flight jobs finish. Call Stop() to signal shutdown.
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

// Enqueue submits a job. It is non-blocking; if the queue is full the job is
// dropped and an error is logged.
func (w *Worker) Enqueue(job Job) {
	select {
	case w.queue <- job:
	default:
		w.log.Warn().Msg("worker: queue full, dropping job")
	}
}

// Stop drains the queue and waits for in-flight jobs to finish.
func (w *Worker) Stop() {
	close(w.queue)
	w.wg.Wait()
}
