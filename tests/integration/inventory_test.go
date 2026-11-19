package integration

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/migrations"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/database"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
)

var base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func migratedPool(t *testing.T) (*pgxpool.Pool, *inventory.Service) {
	t.Helper()
	pool := testPool(t)
	migs, err := database.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := database.Migrate(ctx, pool, migs, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (slug, name) VALUES ('demo', 'Demo'), ('other', 'Other')`); err != nil {
		t.Fatal(err)
	}
	return pool, inventory.NewService(inventory.NewStore(pool))
}

func count(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func TestInventoryImportLifecycle(t *testing.T) {
	pool, svc := migratedPool(t)
	ctx := context.Background()

	v1 := synthetic.Generate(synthetic.Options{Seed: 42, Resources: 1000, CapturedAt: base})
	n1 := len(v1.Snapshot.Resources)

	// 1. First import creates everything.
	rep, err := svc.Import(ctx, "demo", "tester", v1.Snapshot)
	if err != nil {
		t.Fatalf("import v1: %v", err)
	}
	if rep.Duplicate || rep.Created != n1 || rep.Updated+rep.Deleted+rep.Unchanged != 0 {
		t.Fatalf("v1 report: %+v", rep.ImportSummary)
	}
	if got := count(t, pool, `SELECT count(*) FROM resources`); got != n1 {
		t.Fatalf("resources = %d, want %d", got, n1)
	}

	// 2. Re-importing the identical snapshot is idempotent.
	again, err := svc.Import(ctx, "demo", "tester", v1.Snapshot)
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if !again.Duplicate || again.ImportID != rep.ImportID {
		t.Fatalf("re-import not detected as duplicate: %+v", again.ImportSummary)
	}
	// Who imported is recorded and audited once (a duplicate is not a new import).
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE action = 'inventory.import' AND actor = 'tester' AND target_id = $1`, rep.ImportID); n != 1 {
		t.Errorf("inventory.import audit events = %d, want 1", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM inventory_imports WHERE id = $1 AND imported_by = 'tester'`, rep.ImportID); n != 1 {
		t.Error("imported_by not recorded")
	}
	if count(t, pool, `SELECT count(*) FROM resources`) != n1 ||
		count(t, pool, `SELECT count(*) FROM inventory_imports`) != 1 ||
		count(t, pool, `SELECT count(*) FROM resource_versions`) != n1 {
		t.Fatal("duplicate import changed stored state")
	}
	eventsAfterV1 := count(t, pool, `SELECT count(*) FROM outbox_events`)
	if eventsAfterV1 != n1+1 { // one per resource + import.completed
		t.Fatalf("outbox events = %d, want %d", eventsAfterV1, n1+1)
	}

	// 3. Drifted snapshot: detected changes match the ground truth.
	v2, m := synthetic.Mutate(v1, synthetic.MutateOptions{Seed: 2, Modify: 25, Delete: 10, Add: 15, CapturedAt: base.Add(24 * time.Hour)})
	rep2, err := svc.Import(ctx, "demo", "tester", v2.Snapshot)
	if err != nil {
		t.Fatalf("import v2: %v", err)
	}
	if rep2.Created != len(m.Added) || rep2.Deleted != len(m.Deleted) || rep2.Updated < len(m.Modified) {
		t.Fatalf("v2 counts %+v vs truth modified=%d deleted=%d added=%d",
			rep2.ImportSummary, len(m.Modified), len(m.Deleted), len(m.Added))
	}
	changed := map[string]inventory.Change{}
	for _, c := range rep2.Changes {
		changed[c.ResourceID] = c
	}
	for _, id := range m.Modified {
		if c := changed[id]; c.Type != inventory.ChangeUpdated || len(c.ChangedPaths) == 0 {
			t.Errorf("modified %s: %+v", id, c)
		}
	}
	if got := count(t, pool, `SELECT count(*) FROM resources WHERE deleted_at IS NULL`); got != len(v2.Snapshot.Resources) {
		t.Errorf("live resources = %d, want %d", got, len(v2.Snapshot.Resources))
	}
	wantEvents := eventsAfterV1 + rep2.Created + rep2.Updated + rep2.Deleted + 1
	if got := count(t, pool, `SELECT count(*) FROM outbox_events`); got != wantEvents {
		t.Errorf("events = %d, want %d (no events for unchanged resources)", got, wantEvents)
	}

	// 4. Resource detail exposes history.
	page, err := svc.ListResources(ctx, "demo", inventory.ListFilter{IncludeDeleted: true, Limit: 500})
	if err != nil || len(page.Items) != 500 || page.NextCursor == "" {
		t.Fatalf("list page: %d items cursor=%q err=%v", len(page.Items), page.NextCursor, err)
	}
	var target string
	for _, it := range page.Items {
		if it.ResourceID == m.Modified[0] {
			target = it.ID
		}
	}
	if target == "" {
		p2, _ := svc.ListResources(ctx, "demo", inventory.ListFilter{IncludeDeleted: true, Limit: 500, After: page.NextCursor})
		p3, _ := svc.ListResources(ctx, "demo", inventory.ListFilter{IncludeDeleted: true, Limit: 500, After: p2.NextCursor})
		for _, it := range append(p2.Items, p3.Items...) {
			if it.ResourceID == m.Modified[0] {
				target = it.ID
			}
		}
	}
	d, err := svc.GetResource(ctx, "demo", target)
	if err != nil || d.CurrentVersion != 2 || len(d.Versions) != 2 || d.Versions[0].ChangeType != inventory.ChangeUpdated {
		t.Fatalf("detail for %s: version=%d versions=%+v err=%v", m.Modified[0], d.CurrentVersion, d.Versions, err)
	}

	// 5. Out-of-order (older) snapshot is rejected and changes nothing.
	old := v1.Snapshot
	old.CapturedAt = base.Add(time.Hour) // newer than v1 but older than v2
	old.Account.Name = "renamed"
	if _, err := svc.Import(ctx, "demo", "tester", old); !errors.Is(err, inventory.ErrStaleSnapshot) {
		t.Fatalf("stale import: want ErrStaleSnapshot, got %v", err)
	}
	if count(t, pool, `SELECT count(*) FROM inventory_imports`) != 2 {
		t.Fatal("stale import was recorded")
	}

	// 6. Tenant isolation: another tenant sees nothing.
	other, err := svc.ListResources(ctx, "other", inventory.ListFilter{})
	if err != nil || len(other.Items) != 0 {
		t.Fatalf("tenant isolation: %d items, err %v", len(other.Items), err)
	}
	if _, err := svc.GetResource(ctx, "other", target); !errors.Is(err, inventory.ErrNotFound) {
		t.Fatalf("cross-tenant get: want ErrNotFound, got %v", err)
	}
	if _, err := svc.Import(ctx, "nope", "tester", v1.Snapshot); !errors.Is(err, inventory.ErrTenantNotFound) {
		t.Fatalf("unknown tenant: %v", err)
	}
}

func TestConcurrentIdenticalImportsCreateOneImport(t *testing.T) {
	pool, svc := migratedPool(t)
	snap := synthetic.Generate(synthetic.Options{Seed: 9, Resources: 200, CapturedAt: base}).Snapshot

	const workers = 6
	var wg sync.WaitGroup
	results := make(chan inventory.ImportReport, workers)
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := svc.Import(context.Background(), "demo", "tester", snap)
			if err != nil {
				errs <- err
				return
			}
			results <- r
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent import: %v", err)
	}
	ids, fresh := map[string]bool{}, 0
	for r := range results {
		ids[r.ImportID] = true
		if !r.Duplicate {
			fresh++
		}
	}
	if len(ids) != 1 || fresh != 1 {
		t.Fatalf("want 1 import and 1 non-duplicate, got ids=%d fresh=%d", len(ids), fresh)
	}
	if got := count(t, pool, `SELECT count(*) FROM resources`); got != len(snap.Resources) {
		t.Fatalf("resources = %d, want %d", got, len(snap.Resources))
	}
}

func TestSecretsAreNeverPersisted(t *testing.T) {
	pool, svc := migratedPool(t)
	snap := synthetic.Generate(synthetic.Options{Seed: 1, Resources: 30, CapturedAt: base}).Snapshot
	snap.Resources[0].Configuration["master_password"] = "Sup3r-Secret-Value"
	if _, err := svc.Import(context.Background(), "demo", "tester", snap); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`SELECT count(*) FROM resources WHERE configuration::text LIKE '%Sup3r-Secret-Value%'`,
		`SELECT count(*) FROM resource_versions WHERE snapshot::text LIKE '%Sup3r-Secret-Value%'`,
		`SELECT count(*) FROM outbox_events WHERE payload::text LIKE '%Sup3r-Secret-Value%'`,
	} {
		if n := count(t, pool, q); n != 0 {
			t.Errorf("secret persisted: %s -> %d", q, n)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM inventory_imports WHERE warnings::text LIKE '%sensitive_attribute_redacted%'`); n != 1 {
		t.Error("redaction warning not recorded")
	}
}

func TestResourceVersionsAreAppendOnly(t *testing.T) {
	pool, svc := migratedPool(t)
	snap := synthetic.Generate(synthetic.Options{Seed: 3, Resources: 20, CapturedAt: base}).Snapshot
	if _, err := svc.Import(context.Background(), "demo", "tester", snap); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(context.Background(), `UPDATE resource_versions SET change_type = 'deleted'`)
	if err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("want append-only rejection, got %v", err)
	}
}
