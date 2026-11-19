// Package retention deletes data that has outlived its usefulness so tables
// do not grow without limit. It never touches the audit log, resource
// history or remediations: those are the evidence trail.
package retention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/telemetry"
)

// Policy says what to keep. Zero values disable that rule.
type Policy struct {
	OutboxPublishedFor time.Duration // keep published outbox events this long (default 7 days)
	InvestigationsFor  time.Duration // keep investigations this long (default 180 days)
	RunsPerTenant      int           // keep this many compliance, risk and drift runs per tenant and key (default 50)
	// RunsMinAge: runs younger than this are never deleted, whatever their
	// count (default 31 days). Risk scoring derives how long a finding has
	// been failing from these runs and saturates at 30 days, so a shorter
	// history would silently cap the age factor and understate first_seen.
	RunsMinAge    time.Duration
	MLRunsPerKind int // keep this many ML runs per tenant and kind (default 20)
}

// DefaultPolicy is the policy used unless configured otherwise.
func DefaultPolicy() Policy {
	return Policy{OutboxPublishedFor: 7 * 24 * time.Hour, InvestigationsFor: 180 * 24 * time.Hour, RunsPerTenant: 50,
		RunsMinAge: 31 * 24 * time.Hour, MLRunsPerKind: 20}
}

// Result counts deleted rows per table.
type Result map[string]int64

// RunOnce applies the policy in one transaction. A transaction-scoped
// advisory lock makes concurrent runs (several API replicas) skip instead
// of competing.
func RunOnce(ctx context.Context, pool *pgxpool.Pool, p Policy) (Result, error) {
	res := Result{}
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('aegis:retention'))`).Scan(&got); err != nil {
			return err
		}
		if !got {
			return nil // another instance is running retention
		}
		del := func(name, sql string, args ...any) error {
			tag, err := tx.Exec(ctx, sql, args...)
			if err != nil {
				return fmt.Errorf("retention %s: %w", name, err)
			}
			res[name] += tag.RowsAffected()
			return nil
		}
		// Operational tables: deleted directly.
		if p.OutboxPublishedFor > 0 {
			if err := del("outbox_events", `DELETE FROM outbox_events WHERE published_at < now() - $1::interval`, interval(p.OutboxPublishedFor)); err != nil {
				return err
			}
		}
		if err := del("idempotency_keys", `DELETE FROM idempotency_keys WHERE created_at < now() - interval '24 hours'`); err != nil {
			return err
		}
		// Evidence: only through aegis_retention_purge (migration 0023), which
		// enforces minimum retention; the runtime role cannot delete it.
		var runs, ml *int
		var runsAge, inv *string
		if p.RunsPerTenant > 0 {
			runs, runsAge = &p.RunsPerTenant, ptr(interval(p.RunsMinAge))
		}
		if p.InvestigationsFor > 0 {
			inv = ptr(interval(p.InvestigationsFor))
		}
		if p.MLRunsPerKind > 0 {
			ml = &p.MLRunsPerKind
		}
		var counts map[string]int64
		if err := tx.QueryRow(ctx, `SELECT aegis_retention_purge($1, $2::interval, $3::interval, $4)`, runs, runsAge, inv, ml).Scan(&counts); err != nil {
			return fmt.Errorf("retention purge: %w", err)
		}
		for k, n := range counts {
			res[k] += n
		}
		return nil
	})
	return res, err
}

func interval(d time.Duration) string { return fmt.Sprintf("%d seconds", int64(d.Seconds())) }

func ptr[T any](v T) *T { return &v }

// Run applies the policy every interval until ctx is cancelled.
func Run(ctx context.Context, pool *pgxpool.Pool, p Policy, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	job := telemetry.NewJob("retention")
	for {
		start := time.Now()
		res, err := RunOnce(ctx, pool, p)
		if ctx.Err() == nil {
			job.Observe(start, err)
		}
		switch {
		case err != nil && ctx.Err() == nil:
			log.Warn("retention run failed", "error", err)
		case len(res) > 0:
			var total int64
			for _, n := range res {
				total += n
			}
			if total > 0 {
				log.Info("retention removed old rows", "deleted", res)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
