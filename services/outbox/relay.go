// Package outbox publishes events written by the transactional outbox.
//
// Business writes insert outbox rows in the same transaction, so an event
// exists if and only if its change committed. The relay claims unpublished
// rows with FOR UPDATE SKIP LOCKED (several relays never publish the same
// row concurrently), publishes them with the row ID as the message ID (the
// broker drops duplicates inside its de-duplication window), and marks them
// published. Delivery is at-least-once; consumers must be idempotent by ID.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Event is one outbox row as published.
type Event struct {
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	AggregateType string          `json:"aggregate_type"`
	AggregateID   string          `json:"aggregate_id"`
	Type          string          `json:"event_type"`
	Payload       json.RawMessage `json:"payload"`
	CreatedAt     time.Time       `json:"created_at"`
}

// Publisher sends one event. msgID is used for broker-side de-duplication.
type Publisher interface {
	Publish(ctx context.Context, subject, msgID string, data []byte) error
}

// Relay moves outbox rows to the publisher.
type Relay struct {
	Pool        *pgxpool.Pool
	Pub         Publisher
	Log         *slog.Logger
	Batch       int           // rows per claim (default 100)
	Interval    time.Duration // idle poll interval (default 1s)
	MaxAttempts int           // rows that failed this often are parked (default 10)
	Metrics     Metrics
}

// Metrics receives relay counters; nil-safe no-op by default.
type Metrics interface {
	Published(n int)
	Failed(n int)
	Backlog(n int64)
}

type noMetrics struct{}

func (noMetrics) Published(int)   {}
func (noMetrics) Failed(int)      {}
func (noMetrics) Backlog(n int64) {}

var unsafeToken = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// Subject is aegis.<tenant>.<aggregate>.<event>, with tokens made safe for
// NATS subjects (no dots, wildcards or spaces).
func Subject(e Event) string {
	tok := func(s string) string {
		s = unsafeToken.ReplaceAllString(strings.ReplaceAll(s, ".", "_"), "_")
		if s == "" {
			return "_"
		}
		return s
	}
	return "aegis." + tok(e.TenantID) + "." + tok(e.AggregateType) + "." + tok(e.Type)
}

func (r *Relay) defaults() {
	if r.Batch <= 0 {
		r.Batch = 100
	}
	if r.Interval <= 0 {
		r.Interval = time.Second
	}
	if r.MaxAttempts <= 0 {
		r.MaxAttempts = 10
	}
	if r.Metrics == nil {
		r.Metrics = noMetrics{}
	}
	if r.Log == nil {
		r.Log = slog.New(slog.DiscardHandler)
	}
}

// RunOnce claims and publishes one batch. It returns how many rows were
// published and how many failed.
func (r *Relay) RunOnce(ctx context.Context) (published, failed int, err error) {
	r.defaults()
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT id, tenant_id, aggregate_type, aggregate_id, event_type, payload, created_at
		FROM outbox_events WHERE published_at IS NULL AND attempts < $1
		ORDER BY created_at, id LIMIT $2 FOR UPDATE SKIP LOCKED`, r.MaxAttempts, r.Batch)
	if err != nil {
		return 0, 0, err
	}
	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TenantID, &e.AggregateType, &e.AggregateID, &e.Type, &e.Payload, &e.CreatedAt); err != nil {
			rows.Close()
			return 0, 0, err
		}
		events = append(events, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	for _, e := range events {
		data, _ := json.Marshal(e)
		if perr := r.Pub.Publish(ctx, Subject(e), e.ID, data); perr != nil {
			failed++
			msg := perr.Error()
			if len(msg) > 500 {
				msg = msg[:500]
			}
			if _, err := tx.Exec(ctx, `UPDATE outbox_events SET attempts = attempts + 1, last_error = $2 WHERE id = $1`, e.ID, msg); err != nil {
				return published, failed, err
			}
			if errors.Is(perr, context.Canceled) || errors.Is(perr, context.DeadlineExceeded) {
				break
			}
			continue
		}
		published++
		if _, err := tx.Exec(ctx, `UPDATE outbox_events SET published_at = now(), attempts = attempts + 1, last_error = NULL WHERE id = $1`, e.ID); err != nil {
			return published, failed, err
		}
	}
	// Commit with a fresh context so a shutdown mid-batch still records what
	// was already published (re-publishing is safe, but wasteful).
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := tx.Commit(cctx); err != nil {
		return 0, 0, err
	}
	r.Metrics.Published(published)
	r.Metrics.Failed(failed)
	return published, failed, nil
}

// Run relays until ctx is cancelled. Full batches are followed immediately by
// the next claim; otherwise it waits Interval (longer after failures).
func (r *Relay) Run(ctx context.Context) error {
	r.defaults()
	backoff := r.Interval
	for {
		pub, failed, err := r.RunOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		var backlog int64
		if qerr := r.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE published_at IS NULL`).Scan(&backlog); qerr == nil {
			r.Metrics.Backlog(backlog)
		}
		wait := r.Interval
		switch {
		case err != nil:
			r.Log.Warn("outbox relay batch failed", "error", err)
			wait = backoff
			backoff = min(backoff*2, 30*time.Second)
		case failed > 0:
			r.Log.Warn("outbox events failed to publish", "failed", failed, "published", pub)
			wait = backoff
			backoff = min(backoff*2, 30*time.Second)
		default:
			backoff = r.Interval
			if pub == r.Batch {
				wait = 0
			}
		}
		if wait == 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}
