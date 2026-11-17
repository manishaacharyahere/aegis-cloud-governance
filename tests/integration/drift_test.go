package integration

import (
	"context"
	"errors"
	"os"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/drift"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
)

func TestDriftLifecycle(t *testing.T) {
	opaURL := os.Getenv("AEGIS_TEST_OPA_URL")
	if opaURL == "" {
		t.Skip("AEGIS_TEST_OPA_URL not set")
	}
	pool, inv := migratedPool(t)
	ctx := context.Background()
	cat, _ := compliance.LoadCatalog()
	svc := &drift.Service{Pool: pool, OPA: testOPA(opaURL), Config: drift.DefaultConfig(), RuleSeverity: cat.RuleSeverities()}

	if _, err := svc.Compare(ctx, "demo", "", "alice"); !errors.Is(err, drift.ErrNoInventory) {
		t.Fatalf("no inventory: %v", err)
	}
	v1 := synthetic.Generate(synthetic.Options{Seed: 42, Resources: 1000, CapturedAt: base})
	if _, err := inv.Import(ctx, "demo", v1.Snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Compare(ctx, "demo", "", "alice"); !errors.Is(err, drift.ErrNoBaseline) {
		t.Fatalf("no baseline: %v", err)
	}
	b1, err := svc.ApproveBaseline(ctx, "demo", "", "alice", "initial approval")
	if err != nil || b1.ResourceCount != len(v1.Snapshot.Resources) || b1.Status != "active" {
		t.Fatalf("baseline: %+v %v", b1, err)
	}

	// No change since approval: no drift.
	rep, err := svc.Compare(ctx, "demo", "", "alice")
	if err != nil || len(rep.Items) != 0 {
		t.Fatalf("clean compare: %d items, err %v", len(rep.Items), err)
	}

	// Inject drift and observe it.
	v2, m := synthetic.Mutate(v1, synthetic.MutateOptions{Seed: 5, Modify: 30, Delete: 10, Add: 12, CapturedAt: base.Add(24 * time.Hour)})
	if _, err := inv.Import(ctx, "demo", v2.Snapshot); err != nil {
		t.Fatal(err)
	}
	rep, err = svc.Compare(ctx, "demo", "", "bob")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	byID := map[string]drift.Item{}
	for _, it := range rep.Items {
		got[it.Category] = append(got[it.Category], it.ResourceID)
		byID[it.ResourceID] = it
	}
	for k := range got {
		sort.Strings(got[k])
	}
	if !slices.Equal(got[drift.CategoryDeleted], m.Deleted) || !slices.Equal(got[drift.CategoryUnmanaged], m.Added) {
		t.Errorf("deleted/unmanaged mismatch:\n deleted %v vs %v\n unmanaged %v vs %v",
			got[drift.CategoryDeleted], m.Deleted, got[drift.CategoryUnmanaged], m.Added)
	}
	modified := 0
	for _, id := range m.Modified {
		if _, ok := byID[id]; ok {
			modified++
		} else {
			t.Errorf("modified %s not reported", id)
		}
	}
	if total := len(m.Modified) + len(m.Deleted) + len(m.Added); len(rep.Items) != total {
		t.Errorf("items = %d, ground truth = %d (no false drift allowed)", len(rep.Items), total)
	}

	// Security drift is tied to the policy rule it now violates.
	typ := map[string]string{}
	for _, r := range v1.Snapshot.Resources {
		typ[r.ResourceID] = r.ResourceType
	}
	for _, id := range m.Modified {
		it := byID[id]
		switch typ[id] {
		case "aws_security_group":
			if it.Category != drift.CategorySecurity || it.Severity != "critical" || !slices.Contains(it.NewFailures, "AEGIS-NET-001") {
				// Already-open groups gain a duplicate rule: still security drift, but no *new* failure.
				if !(it.Category == drift.CategorySecurity && len(it.NewFailures) == 0) {
					t.Errorf("sg %s: %+v", id, it)
				}
			}
		case "aws_instance":
			if it.Category != drift.CategoryCost {
				t.Errorf("instance %s: %+v", id, it)
			}
		}
	}

	// Stored report round-trips and filters.
	stored, err := svc.GetReport(ctx, "demo", rep.ID, drift.CategorySecurity, "high")
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range stored.Items {
		if it.Category != drift.CategorySecurity || (it.Severity != "high" && it.Severity != "critical") {
			t.Errorf("filter leak: %+v", it)
		}
	}
	if stored.PolicyBundleSHA256 == "" || stored.ConfigSHA256 != drift.DefaultConfig().SHA256() || stored.BaselineID != b1.ID {
		t.Errorf("provenance: %+v", stored)
	}
	if _, err := svc.GetReport(ctx, "other", rep.ID, "", ""); !errors.Is(err, drift.ErrNotFound) {
		t.Errorf("cross-tenant read: %v", err)
	}
	if _, err := svc.GetReport(ctx, "demo", rep.ID, "", "urgent"); !errors.Is(err, drift.ErrInvalid) {
		t.Errorf("bad severity: %v", err)
	}

	// Approving the drifted state makes it the new baseline; drift disappears.
	b2, err := svc.ApproveBaseline(ctx, "demo", "", "carol", "accept Q4 changes")
	if err != nil {
		t.Fatal(err)
	}
	list, _ := svc.ListBaselines(ctx, "demo")
	active := 0
	for _, b := range list {
		if b.Status == "active" {
			active++
			if b.ID != b2.ID {
				t.Error("wrong baseline active")
			}
		}
	}
	if active != 1 || len(list) != 2 {
		t.Fatalf("baselines: %+v", list)
	}
	if rep, _ := svc.Compare(ctx, "demo", "", "alice"); len(rep.Items) != 0 {
		t.Fatalf("drift after re-approval: %d", len(rep.Items))
	}

	// Three successful compares, listed newest first across pages.
	page1, next, err := svc.ListReports(ctx, "demo", "", 2)
	if err != nil || len(page1) != 2 || next == "" || len(page1[0].Items) != 0 {
		t.Fatalf("reports page 1: %d %q %v", len(page1), next, err)
	}
	page2, next2, err := svc.ListReports(ctx, "demo", next, 2)
	if err != nil || len(page2) != 1 || next2 != "" || page2[0].ID == page1[0].ID || page2[0].ID == page1[1].ID {
		t.Fatalf("reports page 2: %d %q %v", len(page2), next2, err)
	}
	if other, _, _ := svc.ListReports(ctx, "other", "", 10); len(other) != 0 {
		t.Errorf("reports leak across tenants: %d", len(other))
	}
	if _, _, err := svc.ListReports(ctx, "demo", "not-a-cursor", 10); !errors.Is(err, drift.ErrInvalid) {
		t.Errorf("bad cursor: %v", err)
	}

	var audited int
	pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action IN ('drift.baseline.approve', 'drift.compare')`).Scan(&audited)
	if audited != 5 {
		t.Errorf("audit events = %d, want 5 (2 approvals + 3 successful compares; failed ones record nothing)", audited)
	}
	t.Logf("drift: %d items (modified %d/%d, deleted %d, unmanaged %d) by severity %v",
		len(rep.Items), modified, len(m.Modified), len(m.Deleted), len(m.Added), stored.Counts["by_severity"])
}
