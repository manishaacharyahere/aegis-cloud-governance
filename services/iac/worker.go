package iac

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Queue is the subset of Store the worker needs (fakeable in tests).
type Queue interface {
	Claim(ctx context.Context, owner string, lease time.Duration) (*Job, error)
	Renew(ctx context.Context, j *Job, owner string, lease time.Duration) error
	Complete(ctx context.Context, j *Job, owner string, r Result) error
	Fail(ctx context.Context, j *Job, owner string, cause error, base, maxDelay time.Duration) (bool, error)
}

// Scanner runs one scan.
type Scanner interface {
	Run(ctx context.Context, fixture string) (Result, error)
}

// Worker processes scans with bounded concurrency.
//
// Reliability: jobs are leased, the lease is renewed while running, and a
// crashed worker's job is reclaimed after its lease expires. On shutdown the
// worker stops claiming, lets in-flight jobs finish for up to DrainTimeout,
// then cancels them; cancelled jobs are re-queued as retryable.
type Worker struct {
	Queue        Queue
	Scanner      Scanner
	Log          *slog.Logger
	ID           string
	Concurrency  int
	PollInterval time.Duration
	Lease        time.Duration
	JobTimeout   time.Duration
	DrainTimeout time.Duration
	BackoffBase  time.Duration
	BackoffMax   time.Duration
}

func (w *Worker) defaults() {
	if w.Concurrency <= 0 {
		w.Concurrency = 2
	}
	if w.PollInterval <= 0 {
		w.PollInterval = 2 * time.Second
	}
	if w.Lease <= 0 {
		w.Lease = 2 * time.Minute
	}
	if w.JobTimeout <= 0 {
		w.JobTimeout = 15 * time.Minute
	}
	if w.DrainTimeout <= 0 {
		w.DrainTimeout = 30 * time.Second
	}
	if w.BackoffBase <= 0 {
		w.BackoffBase = 5 * time.Second
	}
	if w.BackoffMax <= 0 {
		w.BackoffMax = 5 * time.Minute
	}
}

// Run blocks until ctx is cancelled and all in-flight jobs have stopped.
func (w *Worker) Run(ctx context.Context) error {
	w.defaults()
	// Jobs run on their own context so shutdown can drain them.
	jobCtx, cancelJobs := context.WithCancel(context.Background())
	defer cancelJobs()

	slots := make(chan struct{}, w.Concurrency)
	var wg sync.WaitGroup
	w.Log.Info("worker started", "worker_id", w.ID, "concurrency", w.Concurrency)

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case slots <- struct{}{}:
		}
		job, err := w.Queue.Claim(ctx, w.ID, w.Lease)
		if err != nil || job == nil {
			<-slots
			if err != nil && !errors.Is(err, context.Canceled) {
				w.Log.Error("claim failed", "error", err)
			}
			select {
			case <-ctx.Done():
				break loop
			case <-time.After(w.PollInterval):
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			w.process(jobCtx, job)
		}()
	}

	w.Log.Info("worker draining", "timeout", w.DrainTimeout)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(w.DrainTimeout):
		w.Log.Warn("drain timeout; cancelling in-flight jobs")
		cancelJobs()
		<-done
	}
	w.Log.Info("worker stopped")
	return nil
}

func (w *Worker) process(parent context.Context, j *Job) {
	log := w.Log.With("scan_id", j.ScanID, "attempt", j.Attempt, "fixture", j.SourceRef)
	// A reclaimed job whose previous worker died on the final attempt.
	if j.Attempt > j.MaxAttempts {
		w.fail(context.Background(), log, j, fmt.Errorf("exceeded %d attempts (previous worker lost its lease)", j.MaxAttempts))
		return
	}

	ctx, cancel := context.WithTimeout(parent, w.JobTimeout)
	defer cancel()

	// Heartbeat: renew the lease; stop the job if it was lost.
	hbDone := make(chan struct{})
	go func() {
		defer close(hbDone)
		t := time.NewTicker(w.Lease / 3)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := w.Queue.Renew(context.Background(), j, w.ID, w.Lease); err != nil {
					log.Warn("lease renewal failed; abandoning job", "error", err)
					cancel()
					return
				}
			}
		}
	}()

	start := time.Now()
	log.Info("scan started")
	res, err := w.Scanner.Run(ctx, j.SourceRef)
	cancel()
	<-hbDone

	// Persist the outcome even if shutdown cancelled the job context.
	bg, bgCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer bgCancel()
	if err != nil {
		if errors.Is(err, context.Canceled) {
			err = Retryable(fmt.Errorf("interrupted: %w", err))
		}
		w.fail(bg, log, j, err)
		return
	}
	if err := w.Queue.Complete(bg, j, w.ID, res); err != nil {
		log.Error("storing results failed", "error", err)
		if !errors.Is(err, ErrLeaseLost) {
			w.fail(bg, log, j, Retryable(fmt.Errorf("store results: %w", err)))
		}
		return
	}
	log.Info("scan succeeded", "findings", len(res.Findings), "duration", time.Since(start))
}

func (w *Worker) fail(ctx context.Context, log *slog.Logger, j *Job, cause error) {
	final, err := w.Queue.Fail(ctx, j, w.ID, cause, w.BackoffBase, w.BackoffMax)
	if err != nil {
		log.Error("recording failure failed", "error", err, "cause", cause)
		return
	}
	log.Warn("scan failed", "final", final, "retryable", IsRetryable(cause), "error", cause)
}
