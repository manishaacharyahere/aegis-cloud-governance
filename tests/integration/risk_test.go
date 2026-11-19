package integration

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/risk"
)

func TestRiskAssessmentLifecycle(t *testing.T) {
	opaURL := os.Getenv("AEGIS_TEST_OPA_URL")
	if opaURL == "" {
		t.Skip("AEGIS_TEST_OPA_URL not set")
	}
	pool, inv := migratedPool(t)
	ctx := context.Background()
	cat, _ := compliance.LoadCatalog()
	rules := map[string]risk.RuleInfo{}
	counts := cat.ControlCounts()
	for id, sev := range cat.RuleSeverities() {
		rules[id] = risk.RuleInfo{Severity: sev, Controls: counts[id]}
	}
	now := time.Now().UTC()
	rsvc := &risk.Service{Pool: pool, Rules: rules, Now: func() time.Time { return now }}

	ds := synthetic.Generate(synthetic.Options{Seed: 42, Resources: 1000, CapturedAt: base})
	if _, err := inv.Import(ctx, "demo", "tester", ds.Snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := rsvc.Assess(ctx, "demo", "alice", risk.DefaultWeights()); !errors.Is(err, risk.ErrNoEvaluation) {
		t.Fatalf("assess before compliance: %v", err)
	}

	// Two compliance runs ten days apart: persistent failures must be aged from the first.
	tenDaysAgo := now.Add(-10 * 24 * time.Hour)
	csvc := &compliance.Service{Pool: pool, Catalog: cat, OPA: testOPA(opaURL), Now: func() time.Time { return tenDaysAgo }}
	if _, err := csvc.EvaluateInventory(ctx, "demo", "tester"); err != nil {
		t.Fatal(err)
	}
	csvc.Now = func() time.Time { return now }
	sum, err := csvc.EvaluateInventory(ctx, "demo", "tester")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := rsvc.Assess(ctx, "demo", "alice", risk.Weights{Severity: 2}); !errors.Is(err, risk.ErrInvalid) {
		t.Fatalf("invalid weights accepted: %v", err)
	}
	run, err := rsvc.Assess(ctx, "demo", "alice", risk.DefaultWeights())
	if err != nil {
		t.Fatal(err)
	}
	if run.Summary.Findings != sum.Fail || len(run.Assessments) != sum.Fail {
		t.Fatalf("assessed %d findings, compliance run has %d failures", run.Summary.Findings, sum.Fail)
	}
	for i, a := range run.Assessments {
		if i > 0 && a.Score > run.Assessments[i-1].Score {
			t.Fatal("assessments not sorted by score")
		}
		if a.FirstSeen == nil || now.Sub(*a.FirstSeen) < 9*24*time.Hour {
			t.Fatalf("%s/%s: first_seen %v should be ~10 days ago", a.RuleID, a.Subject, a.FirstSeen)
		}
		if a.Factors.Age < 30 || a.Factors.Age > 36 {
			t.Fatalf("age factor %.1f for 10 days, want ~33", a.Factors.Age)
		}
		if a.Factors.Exposure > 0 && len(a.AttackPath) == 0 {
			t.Fatalf("exposed finding without an attack path: %+v", a)
		}
	}
	if len(run.Summary.Sensitivity) != 12 || run.Summary.AttackPaths == 0 || run.Summary.GraphEdges == 0 {
		t.Errorf("summary incomplete: %+v", run.Summary)
	}

	stored, err := rsvc.GetRun(ctx, "demo", run.ID, "high", 1000)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range stored.Assessments {
		if a.Band != "critical" && a.Band != "high" {
			t.Fatalf("band filter leaked %s", a.Band)
		}
	}
	if len(stored.Assessments) != run.Summary.ByBand["critical"]+run.Summary.ByBand["high"] {
		t.Errorf("stored high+ = %d, summary = %v", len(stored.Assessments), run.Summary.ByBand)
	}
	if len(stored.Assessments) > 0 && stored.Assessments[0].Score != run.Assessments[0].Score {
		t.Error("stored ordering differs from computed ordering")
	}
	if _, err := rsvc.GetRun(ctx, "other", run.ID, "", 10); !errors.Is(err, risk.ErrNotFound) {
		t.Errorf("cross-tenant read: %v", err)
	}

	paths, err := rsvc.AttackPaths(ctx, "demo", 80, 10)
	if err != nil || len(paths) == 0 || len(paths) > 10 {
		t.Fatalf("attack paths: %d %v", len(paths), err)
	}
	for _, p := range paths {
		if p.Sensitivity < 80 || p.Hops[0].From != risk.Internet {
			t.Fatalf("bad path: %+v", p)
		}
	}
	t.Logf("risk: %d findings, bands %v, vs-severity %+v, %d internet-reachable sensitive targets",
		run.Summary.Findings, run.Summary.ByBand, run.Summary.VsSeverity, run.Summary.AttackPaths)
	for _, s := range run.Summary.Sensitivity {
		t.Logf("  sensitivity %-16s %s: top-20 overlap %.2f, spearman %.3f, band changes %d", s.Factor, s.Change, s.TopKOverlap, s.Spearman, s.BandChanges)
	}
}
