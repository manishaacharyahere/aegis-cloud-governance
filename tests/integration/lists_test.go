package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/access"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/iac"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
)

func TestListScansPaging(t *testing.T) {
	s := iacStore(t)
	ctx := context.Background()
	want := map[string]bool{}
	for i := range 5 {
		sc, _, err := s.Enqueue(ctx, "demo", "insecure-storage", fmt.Sprintf("list-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		want[sc.ID] = true
	}
	seen := map[string]bool{}
	after, pages := "", 0
	for {
		page, next, err := s.List(ctx, "demo", after, 2)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for i, sc := range page {
			if seen[sc.ID] {
				t.Fatalf("scan %s returned twice", sc.ID)
			}
			seen[sc.ID] = true
			if i > 0 && page[i-1].CreatedAt.Before(sc.CreatedAt) {
				t.Error("not newest first")
			}
		}
		if next == "" {
			break
		}
		after = next
	}
	if pages != 3 || len(seen) != len(want) {
		t.Fatalf("pages=%d seen=%d want=%d", pages, len(seen), len(want))
	}
	if other, _, _ := s.List(ctx, "other", "", 50); len(other) != 0 {
		t.Errorf("scans leak across tenants: %d", len(other))
	}
	if _, _, err := s.List(ctx, "demo", "garbage", 10); !errors.Is(err, iac.ErrInvalidCursor) {
		t.Errorf("bad cursor: %v", err)
	}
	if _, _, err := s.List(ctx, "nope", "", 10); !errors.Is(err, iac.ErrTenantNotFound) {
		t.Errorf("unknown tenant: %v", err)
	}
}

func TestResourceTypes(t *testing.T) {
	pool, inv := migratedPool(t)
	ctx := context.Background()
	ds := synthetic.Generate(synthetic.Options{Seed: 3, Resources: 200, CapturedAt: base})
	if _, err := inv.Import(ctx, "demo", ds.Snapshot); err != nil {
		t.Fatal(err)
	}
	types, err := inv.ResourceTypes(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, tc := range types {
		total += tc.Count
	}
	if live := count(t, pool, `SELECT count(*) FROM resources WHERE deleted_at IS NULL`); total != live || len(types) < 5 {
		t.Fatalf("types=%d total=%d live=%d", len(types), total, live)
	}
	if other, _ := inv.ResourceTypes(ctx, "other"); len(other) != 0 {
		t.Errorf("types leak across tenants: %v", other)
	}
	accts, err := inv.ListAccounts(ctx, "demo")
	if err != nil || len(accts) != 1 || accts[0].Resources != total || accts[0].ExternalID != ds.Snapshot.Account.ExternalID {
		t.Fatalf("accounts: %+v %v", accts, err)
	}
	if other, _ := inv.ListAccounts(ctx, "other"); len(other) != 0 {
		t.Errorf("accounts leak across tenants: %v", other)
	}
}

func TestMemberships(t *testing.T) {
	pool, _ := migratedPool(t)
	ctx := context.Background()
	s := &access.Store{Pool: pool}
	if err := s.Bootstrap(ctx, "demo", []string{"root@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Bootstrap(ctx, "other", []string{"root@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Grant(ctx, "demo", "root@example.com", "alice@example.com", access.RoleViewer); err != nil {
		t.Fatal(err)
	}
	if err := s.Grant(ctx, "demo", "root@example.com", "alice@example.com", access.RoleAnalyst); err != nil {
		t.Fatal(err)
	}
	ms, err := s.Memberships(ctx, "alice@example.com", false)
	if err != nil || len(ms) != 1 || ms[0].Slug != "demo" || len(ms[0].Roles) != 2 {
		t.Fatalf("alice: %+v %v", ms, err)
	}
	if ms, _ := s.Memberships(ctx, "root@example.com", false); len(ms) != 2 {
		t.Errorf("root: %+v", ms)
	}
	if ms, _ := s.Memberships(ctx, "nobody@example.com", false); len(ms) != 0 {
		t.Errorf("nobody: %+v", ms)
	}
	if ms, _ := s.Memberships(ctx, "nobody@example.com", true); len(ms) != 2 || len(ms[0].Roles) != 4 {
		t.Errorf("development mode lists every tenant with every role: %+v", ms)
	}
}
