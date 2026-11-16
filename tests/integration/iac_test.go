package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/iac"
)

func iacStore(t *testing.T) *iac.Store {
	t.Helper()
	pool, _ := migratedPool(t)
	return iac.NewStore(pool)
}

func TestScanEnqueueIsIdempotent(t *testing.T) {
	s := iacStore(t)
	ctx := context.Background()
	a, created, err := s.Enqueue(ctx, "demo", "insecure-storage", "key-1")
	if err != nil || !created || a.Status != iac.StatusQueued {
		t.Fatalf("enqueue: %+v created=%v err=%v", a, created, err)
	}
	b, created, err := s.Enqueue(ctx, "demo", "insecure-storage", "key-1")
	if err != nil || created || b.ID != a.ID {
		t.Fatalf("replay: id=%s created=%v err=%v", b.ID, created, err)
	}
	c, created, _ := s.Enqueue(ctx, "demo", "insecure-storage", "")
	d, created2, _ := s.Enqueue(ctx, "demo", "insecure-storage", "")
	if !created || !created2 || c.ID == d.ID {
		t.Fatal("requests without a key must each create a scan")
	}
	if _, err := s.Get(ctx, "other", a.ID); !errors.Is(err, iac.ErrNotFound) {
		t.Fatalf("cross-tenant read: %v", err)
	}
	if _, _, err := s.Enqueue(ctx, "nope", "x", ""); !errors.Is(err, iac.ErrTenantNotFound) {
		t.Fatalf("unknown tenant: %v", err)
	}
}

func TestConcurrentClaimsNeverShareAJob(t *testing.T) {
	s := iacStore(t)
	ctx := context.Background()
	const jobs, workers = 20, 8
	for i := range jobs {
		if _, _, err := s.Enqueue(ctx, "demo", "insecure-storage", fmt.Sprintf("k%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	claimed := map[string]string{}
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner := fmt.Sprintf("w%d", w)
			for {
				j, err := s.Claim(ctx, owner, time.Minute)
				if err != nil {
					t.Error(err)
					return
				}
				if j == nil {
					return
				}
				mu.Lock()
				if prev, dup := claimed[j.ScanID]; dup {
					t.Errorf("scan %s claimed by %s and %s", j.ScanID, prev, owner)
				}
				claimed[j.ScanID] = owner
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(claimed) != jobs {
		t.Fatalf("claimed %d of %d jobs", len(claimed), jobs)
	}
}

func TestExpiredLeaseIsReclaimedAndOldOwnerCannotWrite(t *testing.T) {
	s := iacStore(t)
	ctx := context.Background()
	scan, _, _ := s.Enqueue(ctx, "demo", "iam-wildcard", "")

	j1, err := s.Claim(ctx, "crashed-worker", 50*time.Millisecond)
	if err != nil || j1 == nil {
		t.Fatalf("claim: %v", err)
	}
	if j, _ := s.Claim(ctx, "w2", time.Minute); j != nil {
		t.Fatal("job with a live lease was claimed twice")
	}
	time.Sleep(150 * time.Millisecond) // lease expires: the first worker "crashed"

	j2, err := s.Claim(ctx, "w2", time.Minute)
	if err != nil || j2 == nil || j2.ScanID != scan.ID || j2.Attempt != 2 {
		t.Fatalf("reclaim: %+v %v", j2, err)
	}
	if err := s.Complete(ctx, j1, "crashed-worker", iac.Result{}); !errors.Is(err, iac.ErrLeaseLost) {
		t.Fatalf("stale owner wrote results: %v", err)
	}
	if err := s.Renew(ctx, j1, "crashed-worker", time.Minute); !errors.Is(err, iac.ErrLeaseLost) {
		t.Fatalf("stale owner renewed: %v", err)
	}
	if err := s.Complete(ctx, j2, "w2", iac.Result{}); err != nil {
		t.Fatalf("new owner complete: %v", err)
	}
}

func TestRetryBackoffThenPermanentFailure(t *testing.T) {
	s := iacStore(t)
	ctx := context.Background()
	scan, _, _ := s.Enqueue(ctx, "demo", "iam-wildcard", "")
	transient := iac.Retryable(errors.New("docker unavailable"))

	for attempt := 1; attempt <= 3; attempt++ {
		var j *iac.Job
		deadline := time.Now().Add(5 * time.Second)
		for j == nil && time.Now().Before(deadline) {
			j, _ = s.Claim(ctx, "w", time.Minute)
			if j == nil {
				time.Sleep(20 * time.Millisecond) // wait out the backoff
			}
		}
		if j == nil || j.Attempt != attempt {
			t.Fatalf("attempt %d not claimed: %+v", attempt, j)
		}
		final, err := s.Fail(ctx, j, "w", transient, 10*time.Millisecond, 50*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		if final != (attempt == 3) {
			t.Fatalf("attempt %d final=%v", attempt, final)
		}
	}
	rep, _ := s.Get(ctx, "demo", scan.ID)
	if rep.Status != iac.StatusFailed || rep.Attempts != 3 || rep.ErrorClass != "retryable" {
		t.Fatalf("final state: %+v", rep.Scan)
	}

	// Permanent errors fail immediately.
	scan2, _, _ := s.Enqueue(ctx, "demo", "iam-wildcard", "")
	j, _ := s.Claim(ctx, "w", time.Minute)
	if final, _ := s.Fail(ctx, j, "w", errors.New("invalid terraform"), time.Millisecond, time.Millisecond); !final {
		t.Fatal("permanent error was retried")
	}
	if rep, _ := s.Get(ctx, "demo", scan2.ID); rep.Status != iac.StatusFailed || rep.ErrorClass != "permanent" {
		t.Fatalf("permanent state: %+v", rep.Scan)
	}
}

func TestCompleteStoresReportIdempotently(t *testing.T) {
	s := iacStore(t)
	ctx := context.Background()
	scan, _, _ := s.Enqueue(ctx, "demo", "insecure-storage", "")
	j, _ := s.Claim(ctx, "w", time.Minute)
	res := iac.Result{
		Analysis: iac.Analysis{Summary: iac.Summary{Create: 1}, Resources: []iac.PlannedResource{
			{Address: "aws_db_instance.x", Type: "aws_db_instance", Action: iac.ActionReplace, Destructive: true}}},
		Findings: iac.Merge([]iac.Finding{
			{Source: iac.SourcePolicy, RuleID: "AEGIS-TF-001", Severity: "high", Decision: "deny", ResourceAddress: "aws_db_instance.x"},
			{Source: iac.SourceCheckov, RuleID: "CKV_AWS_16", Severity: "unknown", Decision: "fail", ResourceAddress: "aws_db_instance.x"},
		}),
		ToolVersions:       map[string]string{"terraform": "hashicorp/terraform:1.10.5"},
		PolicyBundleSHA256: "deadbeef",
	}
	if err := s.Complete(ctx, j, "w", res); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Get(ctx, "demo", scan.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Status != iac.StatusSucceeded || len(rep.Findings) != 2 || rep.Blocking != 1 ||
		len(rep.Changes) != 1 || !rep.Changes[0].Destructive || rep.PolicyBundleSHA256 != "deadbeef" ||
		rep.Counts[iac.SourceCheckov]["unknown"] != 1 || rep.PlanSummary == nil || rep.PlanSummary.Create != 1 {
		t.Fatalf("report: %+v", rep)
	}
	// A second completion (e.g. duplicate delivery) is rejected: the lease is gone.
	if err := s.Complete(ctx, j, "w", res); !errors.Is(err, iac.ErrLeaseLost) {
		t.Fatalf("double completion: %v", err)
	}
}

// TestPolicyGroundTruth evaluates every fixture's recorded plan with the real
// OPA server and compares the result with the fixture's expected.json.
func TestPolicyGroundTruth(t *testing.T) {
	opaURL := os.Getenv("AEGIS_TEST_OPA_URL")
	if opaURL == "" {
		t.Skip("AEGIS_TEST_OPA_URL not set; skipping OPA ground-truth test")
	}
	opa := &iac.OPAClient{BaseURL: opaURL, Token: os.Getenv("AEGIS_TEST_OPA_TOKEN")}
	fixtures := []string{"secure-baseline", "insecure-storage", "iam-wildcard", "network-exposure", "missing-logging-tags", "unapproved-region"}
	for _, f := range fixtures {
		t.Run(f, func(t *testing.T) {
			raw, err := os.Open(filepath.Join("..", "..", "services", "iac", "testdata", f+".plan.json"))
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			plan, err := iac.ParsePlan(raw)
			if err != nil {
				t.Fatal(err)
			}
			res, err := opa.Evaluate(context.Background(), iac.Analyze(plan))
			if err != nil {
				t.Fatal(err)
			}
			got := map[[2]string]bool{}
			fired := map[string]bool{}
			for _, x := range res.Findings() {
				got[[2]string{x.RuleID, x.ResourceAddress}] = true
				fired[x.RuleID] = true
			}

			var exp struct {
				MustFire []struct {
					RuleID  string `json:"rule_id"`
					Address string `json:"address"`
				} `json:"must_fire"`
				MustNotFireOn []struct {
					RuleID  string `json:"rule_id"`
					Address string `json:"address"`
				} `json:"must_not_fire_on"`
				MustNotFire []string `json:"must_not_fire"`
			}
			b, err := os.ReadFile(filepath.Join("..", "..", "datasets", "terraform-fixtures", f, "expected.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &exp); err != nil {
				t.Fatal(err)
			}
			for _, m := range exp.MustFire {
				if !got[[2]string{m.RuleID, m.Address}] {
					t.Errorf("false negative: %s on %s", m.RuleID, m.Address)
				}
			}
			for _, m := range exp.MustNotFireOn {
				if got[[2]string{m.RuleID, m.Address}] {
					t.Errorf("false positive: %s on %s", m.RuleID, m.Address)
				}
			}
			for _, r := range exp.MustNotFire {
				if fired[r] {
					t.Errorf("false positive: %s fired", r)
				}
			}
		})
	}
}
