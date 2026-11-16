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
)

// Policy says what to keep. Zero values disable that rule.
type Policy struct {
	OutboxPublishedFor time.Duration // keep published outbox events this long (default 7 days)
	InvestigationsFor  time.Duration // keep investigations this long (default 180 days)
	RunsPerTenant      int           // keep this many compliance, risk and drift runs per tenant (default 50)
	MLRunsPerKind      int           // keep this many ML runs per tenant and kind (default 20)
}

// DefaultPolicy is the policy used unless configured otherwise.
func DefaultPolicy() Policy {
	return Policy{OutboxPublishedFor: 7 * 24 * time.Hour, InvestigationsFor: 180 * 24 * time.Hour, RunsPerTenant: 50, MLRunsPerKind: 20}
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
		if _, err := tx.Exec(ctx, `SET LOCAL aegis.retention = 'on'`); err != nil {
			return err
		}
		del := func(name, sql string, args ...any) error {
			tag, err := tx.Exec(ctx, sql, args...)
			if err != nil {
				return fmt.Errorf("retention %s: %w", name, err)
			}
			res[name] += tag.RowsAffected()
			return nil
		}
		if p.OutboxPublishedFor > 0 {
			if err := del("outbox_events", `DELETE FROM outbox_events WHERE published_at < now() - $1::interval`, interval(p.OutboxPublishedFor)); err != nil {
				return err
			}
		}
		if p.InvestigationsFor > 0 {
			if err := del("investigations", `DELETE FROM investigations WHERE created_at < now() - $1::interval`, interval(p.InvestigationsFor)); err != nil {
				return err
			}
		}
		if p.RunsPerTenant > 0 {
			// Risk runs first: they reference compliance runs. Keep the newest N
			// per tenant, plus any risk run whose compliance run is kept.
			if err := del("risk_runs", `DELETE FROM risk_runs WHERE id IN (
				SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY tenant_id ORDER BY created_at DESC, id) AS n FROM risk_runs) r
				WHERE r.n > $1)`, p.RunsPerTenant); err != nil {
				return err
			}
			if err := del("compliance_runs", `DELETE FROM compliance_runs c WHERE c.id IN (
				SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY tenant_id, source ORDER BY evaluated_at DESC, id) AS n FROM compliance_runs) x
				WHERE x.n > $1)
				AND NOT EXISTS (SELECT 1 FROM risk_runs r WHERE r.compliance_run_id = c.id)`, p.RunsPerTenant); err != nil {
				return err
			}
			if err := del("drift_reports", `DELETE FROM drift_reports WHERE id IN (
				SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY tenant_id, account_id ORDER BY created_at DESC, id) AS n FROM drift_reports) d
				WHERE d.n > $1)`, p.RunsPerTenant); err != nil {
				return err
			}
		}
		if p.MLRunsPerKind > 0 {
			if err := del("ml_runs", `DELETE FROM ml_runs WHERE id IN (
				SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY tenant_id, kind ORDER BY created_at DESC, id) AS n FROM ml_runs) m
				WHERE m.n > $1)`, p.MLRunsPerKind); err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}

func interval(d time.Duration) string { return fmt.Sprintf("%d seconds", int64(d.Seconds())) }

// Run applies the policy every interval until ctx is cancelled.
func Run(ctx context.Context, pool *pgxpool.Pool, p Policy, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		res, err := RunOnce(ctx, pool, p)
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
