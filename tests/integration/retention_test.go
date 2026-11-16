package integration

import (
	"context"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/retention"
)

func TestRetention(t *testing.T) {
	pool, _ := migratedPool(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var tid string
	_ = pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'demo'`).Scan(&tid)

	// Outbox: 3 old published, 2 recent published, 1 old unpublished (kept: not delivered yet).
	exec(`INSERT INTO outbox_events (tenant_id, aggregate_type, aggregate_id, event_type, payload, published_at)
		SELECT $1, 't', g::text, 'e', '{}', now() - interval '30 days' FROM generate_series(1, 3) g`, tid)
	exec(`INSERT INTO outbox_events (tenant_id, aggregate_type, aggregate_id, event_type, payload, published_at)
		SELECT $1, 't', g::text, 'e', '{}', now() - interval '1 day' FROM generate_series(1, 2) g`, tid)
	exec(`INSERT INTO outbox_events (tenant_id, aggregate_type, aggregate_id, event_type, payload, created_at)
		VALUES ($1, 't', 'x', 'e', '{}', now() - interval '60 days')`, tid)

	// Investigations: 2 old, 1 recent. They are append-only for everyone else.
	inv := `INSERT INTO investigations (tenant_id, resource_id, account_id, actor, evidence, evidence_sha256, brief, model_status, model, created_at)
		VALUES ($1, 'r', 'a', 'x', '[]', repeat('0', 64), '{}', 'not_configured', '{}', now() - $2::interval)`
	exec(inv, tid, "200 days")
	exec(inv, tid, "300 days")
	exec(inv, tid, "1 day")
	if _, err := pool.Exec(ctx, `DELETE FROM investigations`); err == nil {
		t.Fatal("investigations must stay append-only outside the retention job")
	}

	// ML runs: 4 forecasts; keep the newest 2.
	exec(`INSERT INTO ml_runs (tenant_id, kind, model, params, data_from, data_to, versions, created_at)
		SELECT $1, 'forecast', 'm', '{}', '2025-01-01', '2025-02-01', '{}', now() - (g || ' days')::interval FROM generate_series(1, 4) g`, tid)
	audit := count(t, pool, `SELECT count(*) FROM audit_events`)

	res, err := retention.RunOnce(ctx, pool, retention.Policy{OutboxPublishedFor: 7 * 24 * time.Hour,
		InvestigationsFor: 180 * 24 * time.Hour, RunsPerTenant: 50, MLRunsPerKind: 2})
	if err != nil {
		t.Fatal(err)
	}
	if res["outbox_events"] != 3 || res["investigations"] != 2 || res["ml_runs"] != 2 {
		t.Fatalf("deleted %v", res)
	}
	if n := count(t, pool, `SELECT count(*) FROM outbox_events WHERE published_at IS NULL`); n != 1 {
		t.Errorf("an undelivered event was deleted (%d left)", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_events`); n != audit {
		t.Errorf("retention must never delete audit events")
	}
	// A second run has nothing to do.
	if res, err := retention.RunOnce(ctx, pool, retention.DefaultPolicy()); err != nil || res["investigations"]+res["outbox_events"] != 0 {
		t.Errorf("second run: %v %v", res, err)
	}
}
