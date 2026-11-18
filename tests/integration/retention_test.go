package integration

import (
	"context"
	"fmt"
	"strings"
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
		InvestigationsFor: 180 * 24 * time.Hour, RunsPerTenant: 50, RunsMinAge: 31 * 24 * time.Hour, MLRunsPerKind: 2})
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

// Retention keeps the newest compliance run for every source key (C22) and
// never deletes runs younger than RunsMinAge (C21).
func TestRetentionKeepsLatestRunPerKeyAndRecentHistory(t *testing.T) {
	pool, _ := migratedPool(t)
	ctx := context.Background()
	var tid string
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'demo'`).Scan(&tid); err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("a", 64)
	if _, err := pool.Exec(ctx, `INSERT INTO policy_bundles (sha256, modules) VALUES ($1, '{}')`, sha); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO catalog_versions (sha256, version, content) VALUES ($1, 'v', '{}')`, sha); err != nil {
		t.Fatal(err)
	}
	run := func(key string, age string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO compliance_runs (tenant_id, source, source_key, source_ref, policy_bundle_sha256,
			catalog_sha256, actor, evaluated_at, pass_count, fail_count, excepted_count)
			VALUES ($1, 'iac_scan', $2, 'r', $3, $3, 'a', now() - $4::interval, 0, 0, 0)`, tid, key, sha, age); err != nil {
			t.Fatal(err)
		}
	}
	run("fixture-a", "90 days") // the only run for fixture-a: must survive
	for i := range 5 {
		run("fixture-b", fmt.Sprintf("%d days", 60+i)) // old runs of fixture-b beyond the count: deleted
	}
	for i := range 5 {
		run("fixture-b", fmt.Sprintf("%d days", i+1)) // recent runs: kept by age
	}
	p := retention.DefaultPolicy()
	p.RunsPerTenant = 2
	if _, err := retention.RunOnce(ctx, pool, p); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, `SELECT count(*) FROM compliance_runs WHERE source_key = 'fixture-a'`); n != 1 {
		t.Errorf("only run for fixture-a deleted: %d left", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM compliance_runs WHERE source_key = 'fixture-b'`); n != 5 {
		t.Errorf("fixture-b runs left = %d, want the 5 recent ones", n)
	}
}
