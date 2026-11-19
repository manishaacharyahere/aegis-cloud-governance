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
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/metric"
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

// transient is implemented by publisher errors that mean "the broker is
// unavailable" rather than "this message was refused".
type transient interface{ Transient() bool }

func isTransient(err error) bool {
	var t transient
	return errors.As(err, &t) && t.Transient()
}

// Relay moves outbox rows to the publisher.
type Relay struct {
	Pool        *pgxpool.Pool
	Pub         Publisher
	Log         *slog.Logger
	Batch       int           // rows per claim (default 100)
	Interval    time.Duration // idle poll interval (default 1s)
	MaxAttempts int           // rows that failed this often are parked (default 10)
	Lease       time.Duration // how long a claim lasts (default 30s; keep below the broker's 2-minute de-duplication window)
	ID          string        // relay identity recorded on claims (default random)
	Metrics     Metrics
}

// Metrics receives relay counters; nil-safe no-op by default.
type Metrics interface {
	Published(n int)
	Failed(n int)
	Backlog(n int64)
	Parked(n int64)
}

type noMetrics struct{}

func (noMetrics) Published(int) {}
func (noMetrics) Failed(int)    {}
func (noMetrics) Backlog(int64) {}
func (noMetrics) Parked(int64)  {}

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
	if r.Lease <= 0 {
		r.Lease = 30 * time.Second
	}
	if r.ID == "" {
		var b [8]byte
		_, _ = rand.Read(b[:])
		r.ID = "relay-" + hex.EncodeToString(b[:])
	}
	if r.Metrics == nil {
		r.Metrics = noMetrics{}
	}
	if r.Log == nil {
		r.Log = slog.New(slog.DiscardHandler)
	}
}

// RunOnce claims, publishes and records one batch. No transaction is held
// while publishing: rows are claimed with a lease in one statement, published,
// then marked in a second statement. If the relay dies in between, the lease
// expires and another relay re-sends; the broker drops the duplicate because
// the lease is shorter than its de-duplication window.
func (r *Relay) RunOnce(ctx context.Context) (published, failed int, err error) {
	r.defaults()
	events, err := r.claim(ctx)
	if err != nil || len(events) == 0 {
		return 0, 0, err
	}
	var ok []string
	type failure struct {
		id, msg string
		count   bool // counts toward MaxAttempts (parking)
	}
	var bad []failure
	var release []string // claimed but not attempted: free them at once
	for i, e := range events {
		data, _ := json.Marshal(e)
		if perr := r.Pub.Publish(ctx, Subject(e), e.ID, data); perr != nil {
			msg := perr.Error()
			if len(msg) > 500 {
				msg = strings.ToValidUTF8(msg[:500], "")
			}
			// A broker outage is not the message's fault: record the error but
			// do not count the attempt, or a few minutes of downtime would park
			// every pending event. Stop the batch; the rest is retried later.
			if isTransient(perr) || ctx.Err() != nil {
				bad = append(bad, failure{e.ID, msg, false})
				for _, rest := range events[i+1:] {
					release = append(release, rest.ID)
				}
				break
			}
			bad = append(bad, failure{e.ID, msg, true})
			continue
		}
		ok = append(ok, e.ID)
	}
	// Record results with a fresh context so a shutdown mid-batch still
	// records what was published.
	mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if len(ok) > 0 {
		if _, err := r.Pool.Exec(mctx, `UPDATE outbox_events SET published_at = now(), attempts = attempts + 1,
			last_error = NULL, claimed_until = NULL, claimed_by = NULL WHERE id = ANY($1) AND claimed_by = $2`, ok, r.ID); err != nil {
			return 0, 0, err
		}
	}
	for _, f := range bad {
		if _, err := r.Pool.Exec(mctx, `UPDATE outbox_events SET attempts = attempts + CASE WHEN $4 THEN 1 ELSE 0 END, last_error = $2,
			claimed_until = NULL, claimed_by = NULL WHERE id = $1 AND claimed_by = $3`, f.id, f.msg, r.ID, f.count); err != nil {
			return len(ok), len(bad), err
		}
	}
	if len(release) > 0 {
		if _, err := r.Pool.Exec(mctx, `UPDATE outbox_events SET claimed_until = NULL, claimed_by = NULL
			WHERE id = ANY($1) AND claimed_by = $2`, release, r.ID); err != nil {
			return len(ok), len(bad), err
		}
	}
	r.Metrics.Published(len(ok))
	r.Metrics.Failed(len(bad))
	return len(ok), len(bad), nil
}

// claim leases up to Batch unpublished rows to this relay in one statement.
func (r *Relay) claim(ctx context.Context) ([]Event, error) {
	rows, err := r.Pool.Query(ctx, `
		UPDATE outbox_events o SET claimed_until = now() + $3::interval, claimed_by = $4
		FROM (SELECT id FROM outbox_events
		      WHERE published_at IS NULL AND attempts < $1 AND (claimed_until IS NULL OR claimed_until < now())
		      ORDER BY created_at, id LIMIT $2 FOR UPDATE SKIP LOCKED) c
		WHERE o.id = c.id
		RETURNING o.id, o.tenant_id, o.aggregate_type, o.aggregate_id, o.event_type, o.payload, o.created_at`,
		r.MaxAttempts, r.Batch, fmt.Sprintf("%d milliseconds", r.Lease.Milliseconds()), r.ID)
	if err != nil {
		return nil, err
	}
	events, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Event, error) {
		var e Event
		return e, row.Scan(&e.ID, &e.TenantID, &e.AggregateType, &e.AggregateID, &e.Type, &e.Payload, &e.CreatedAt)
	})
	sort.Slice(events, func(i, j int) bool { // RETURNING order is not guaranteed
		if !events[i].CreatedAt.Equal(events[j].CreatedAt) {
			return events[i].CreatedAt.Before(events[j].CreatedAt)
		}
		return events[i].ID < events[j].ID
	})
	return events, err
}

// Parked counts events that exceeded the retry limit.
func (r *Relay) Parked(ctx context.Context) (int64, error) {
	r.defaults()
	var n int64
	err := r.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE published_at IS NULL AND attempts >= $1`, r.MaxAttempts).Scan(&n)
	return n, err
}

// RequeueParked gives a tenant's parked events another set of attempts.
func RequeueParked(ctx context.Context, pool *pgxpool.Pool, tenantSlug string, maxAttempts int) (int64, error) {
	if maxAttempts <= 0 {
		maxAttempts = 10
	}
	tag, err := pool.Exec(ctx, `UPDATE outbox_events o SET attempts = 0, claimed_until = NULL, claimed_by = NULL
		FROM tenants t WHERE t.id = o.tenant_id AND t.slug = $1 AND o.published_at IS NULL AND o.attempts >= $2`, tenantSlug, maxAttempts)
	return tag.RowsAffected(), err
}

// Run relays until ctx is cancelled. Full batches are followed immediately by
// the next claim; otherwise it waits Interval (longer after failures).
func (r *Relay) Run(ctx context.Context) error {
	r.defaults()
	backoff := r.Interval
	var lastParked int64
	var sampled time.Time
	for {
		pub, failed, err := r.RunOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		// Gauges are sampled every 15 s, not after every batch: draining a big
		// import would otherwise run two counts per 100 events. The parked
		// warning is logged when the number changes, not every loop.
		if time.Since(sampled) >= 15*time.Second {
			sampled = time.Now()
			var backlog int64
			if qerr := r.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE published_at IS NULL`).Scan(&backlog); qerr == nil {
				r.Metrics.Backlog(backlog)
			} else if ctx.Err() == nil {
				r.Log.Warn("outbox backlog count failed", "error", qerr)
			}
			if parked, perr := r.Parked(ctx); perr == nil {
				r.Metrics.Parked(parked)
				if parked > 0 && parked != lastParked {
					r.Log.Warn("outbox events parked after repeated failures; requeue with POST /api/v1/admin/outbox/requeue", "parked", parked)
				}
				lastParked = parked
			} else if ctx.Err() == nil {
				r.Log.Warn("outbox parked count failed", "error", perr)
			}
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

// OTelMetrics records relay activity as OpenTelemetry instruments.
type OTelMetrics struct {
	published, failed metric.Int64Counter
	backlog, parked   metric.Int64Gauge
}

// NewOTelMetrics creates the relay instruments on m.
func NewOTelMetrics(m metric.Meter) (*OTelMetrics, error) {
	p, err1 := m.Int64Counter("aegis.outbox.published", metric.WithDescription("Outbox events published to the broker"))
	f, err2 := m.Int64Counter("aegis.outbox.failed", metric.WithDescription("Outbox publish attempts that failed"))
	b, err3 := m.Int64Gauge("aegis.outbox.backlog", metric.WithDescription("Outbox events not yet published"))
	k, err4 := m.Int64Gauge("aegis.outbox.parked", metric.WithDescription("Outbox events that exceeded the retry limit"))
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return nil, err
	}
	return &OTelMetrics{published: p, failed: f, backlog: b, parked: k}, nil
}

// Published implements Metrics.
func (o *OTelMetrics) Published(n int) { o.published.Add(context.Background(), int64(n)) }

// Failed implements Metrics.
func (o *OTelMetrics) Failed(n int) { o.failed.Add(context.Background(), int64(n)) }

// Backlog implements Metrics.
func (o *OTelMetrics) Backlog(n int64) { o.backlog.Record(context.Background(), n) }

// Parked implements Metrics.
func (o *OTelMetrics) Parked(n int64) { o.parked.Record(context.Background(), n) }
