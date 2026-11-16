package iac

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memQueue struct {
	mu        sync.Mutex
	jobs      []*Job
	completed map[string]int
	failed    map[string]error
	renewErr  error
	renewals  atomic.Int32
}

func newMemQueue(n int) *memQueue {
	q := &memQueue{completed: map[string]int{}, failed: map[string]error{}}
	for i := range n {
		q.jobs = append(q.jobs, &Job{ScanID: string(rune('a' + i)), SourceRef: "x", Attempt: 1, MaxAttempts: 3})
	}
	return q
}

func (q *memQueue) Claim(context.Context, string, time.Duration) (*Job, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.jobs) == 0 {
		return nil, nil
	}
	j := q.jobs[0]
	q.jobs = q.jobs[1:]
	return j, nil
}
func (q *memQueue) Renew(context.Context, *Job, string, time.Duration) error {
	q.renewals.Add(1)
	return q.renewErr
}
func (q *memQueue) Complete(_ context.Context, j *Job, _ string, _ Result) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.completed[j.ScanID]++
	return nil
}
func (q *memQueue) Fail(_ context.Context, j *Job, _ string, cause error, _, _ time.Duration) (bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.failed[j.ScanID] = cause
	return !IsRetryable(cause), nil
}

type fakeScanner struct {
	delay   time.Duration
	err     error
	running atomic.Int32
	peak    atomic.Int32
}

func (f *fakeScanner) Run(ctx context.Context, _ string) (Result, error) {
	n := f.running.Add(1)
	defer f.running.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case <-time.After(f.delay):
		return Result{}, f.err
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
}

func testWorker(q Queue, s Scanner) *Worker {
	return &Worker{Queue: q, Scanner: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), ID: "w1",
		Concurrency: 2, PollInterval: 5 * time.Millisecond, Lease: 30 * time.Millisecond, DrainTimeout: time.Second}
}

func runFor(t *testing.T, w *Worker, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	if err := w.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerProcessesAllJobsWithBoundedConcurrency(t *testing.T) {
	q := newMemQueue(6)
	s := &fakeScanner{delay: 20 * time.Millisecond}
	runFor(t, testWorker(q, s), 300*time.Millisecond)
	if len(q.completed) != 6 {
		t.Fatalf("completed %d/6", len(q.completed))
	}
	for id, n := range q.completed {
		if n != 1 {
			t.Errorf("job %s completed %d times", id, n)
		}
	}
	if p := s.peak.Load(); p > 2 {
		t.Errorf("concurrency limit exceeded: peak %d", p)
	}
}

func TestWorkerRecordsFailures(t *testing.T) {
	q := newMemQueue(1)
	runFor(t, testWorker(q, &fakeScanner{err: errors.New("bad terraform")}), 100*time.Millisecond)
	if err := q.failed["a"]; err == nil || IsRetryable(err) {
		t.Fatalf("want permanent failure, got %v", err)
	}
}

func TestWorkerFailsJobsBeyondMaxAttempts(t *testing.T) {
	q := newMemQueue(1)
	q.jobs[0].Attempt = 4 // reclaimed after a crash on the 3rd attempt
	s := &fakeScanner{}
	runFor(t, testWorker(q, s), 100*time.Millisecond)
	if q.failed["a"] == nil || s.peak.Load() != 0 {
		t.Fatalf("over-limit job must fail without running: failed=%v ran=%d", q.failed["a"], s.peak.Load())
	}
}

func TestWorkerRenewsLeaseAndAbandonsLostJobs(t *testing.T) {
	q := newMemQueue(1)
	q.renewErr = ErrLeaseLost
	runFor(t, testWorker(q, &fakeScanner{delay: time.Second}), 200*time.Millisecond)
	if q.renewals.Load() == 0 {
		t.Fatal("lease never renewed")
	}
	if q.completed["a"] != 0 {
		t.Fatal("job with a lost lease must not complete")
	}
}

func TestWorkerGracefulShutdownRequeuesInterruptedJobs(t *testing.T) {
	q := newMemQueue(1)
	w := testWorker(q, &fakeScanner{delay: 10 * time.Second})
	w.Lease = time.Minute
	w.DrainTimeout = 50 * time.Millisecond
	start := time.Now()
	runFor(t, w, 50*time.Millisecond)
	if time.Since(start) > 2*time.Second {
		t.Fatal("shutdown did not honour drain timeout")
	}
	if err := q.failed["a"]; err == nil || !IsRetryable(err) {
		t.Fatalf("interrupted job must be re-queued as retryable, got %v", err)
	}
}

func TestBackoffBounds(t *testing.T) {
	base, max := time.Second, 10*time.Second
	for attempt := 1; attempt <= 8; attempt++ {
		ceiling := base << (attempt - 1)
		if ceiling > max {
			ceiling = max
		}
		for range 200 {
			if d := Backoff(attempt, base, max); d < 0 || d > ceiling {
				t.Fatalf("attempt %d: %s outside [0, %s]", attempt, d, ceiling)
			}
		}
	}
}
