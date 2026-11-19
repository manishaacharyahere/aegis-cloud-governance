package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/iac"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
)

// labelRule maps generator ground-truth labels to the rule that must detect them.
var labelRule = map[string]string{
	synthetic.IssuePublicBucket:        "AEGIS-S3-001",
	synthetic.IssueUnencryptedStorage:  "AEGIS-ENC-001",
	synthetic.IssueUnencryptedDatabase: "AEGIS-DB-001",
	synthetic.IssuePublicDatabase:      "AEGIS-DB-002",
	synthetic.IssueWildcardIAM:         "AEGIS-IAM-001",
	synthetic.IssueOpenSSH:             "AEGIS-NET-001",
	synthetic.IssueMissingTags:         "AEGIS-TAG-001",
	synthetic.IssueLoggingDisabled:     "AEGIS-LOG-001",
}

func complianceSvc(t *testing.T) (*pgxpool.Pool, *compliance.Service, synthetic.Dataset) {
	t.Helper()
	opaURL := os.Getenv("AEGIS_TEST_OPA_URL")
	if opaURL == "" {
		t.Skip("AEGIS_TEST_OPA_URL not set")
	}
	pool, inv := migratedPool(t)
	ds := synthetic.Generate(synthetic.Options{Seed: 42, Resources: 1000, CapturedAt: base})
	if _, err := inv.Import(context.Background(), "demo", "tester", ds.Snapshot); err != nil {
		t.Fatal(err)
	}
	cat, err := compliance.LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return pool, &compliance.Service{Pool: pool, Catalog: cat, OPA: testOPA(opaURL)}, ds
}

type evalRow struct{ rule, subject, result, exception string }

func runEvals(t *testing.T, pool *pgxpool.Pool, runID string) map[[2]string]evalRow {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT rule_id, subject, result, coalesce(exception_id::text,'')
		FROM compliance_evaluations WHERE run_id = $1`, runID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[[2]string]evalRow{}
	for rows.Next() {
		var e evalRow
		if err := rows.Scan(&e.rule, &e.subject, &e.result, &e.exception); err != nil {
			t.Fatal(err)
		}
		out[[2]string{e.rule, e.subject}] = e
	}
	return out
}

// TestInventoryPolicyGroundTruth measures the inventory policies against the
// generator's labels: every labelled issue must fail (recall) and every fail
// of a label-backed rule must be labelled (precision).
func TestInventoryPolicyGroundTruth(t *testing.T) {
	pool, svc, ds := complianceSvc(t)
	sum, err := svc.EvaluateInventory(context.Background(), "demo", "tester")
	if err != nil {
		t.Fatal(err)
	}
	evs := runEvals(t, pool, sum.RunID)

	expected := map[[2]string]bool{}
	for id, issues := range ds.Labels {
		for _, is := range issues {
			if rule, ok := labelRule[is]; ok {
				expected[[2]string{rule, id}] = true
			}
		}
	}
	backed := map[string]bool{}
	for _, r := range labelRule {
		backed[r] = true
	}
	tp, fn, fp := 0, 0, 0
	for k := range expected {
		if evs[k].result == compliance.ResultFail {
			tp++
		} else {
			fn++
			t.Errorf("false negative: %s on %s (got %q)", k[0], k[1], evs[k].result)
		}
	}
	for k, e := range evs {
		if backed[e.rule] && e.result == compliance.ResultFail && !expected[k] {
			fp++
			t.Errorf("false positive: %s on %s", k[0], k[1])
		}
	}
	t.Logf("inventory ground truth: tp=%d fn=%d fp=%d over %d evaluations (pass=%d fail=%d)",
		tp, fn, fp, len(evs), sum.Pass, sum.Fail)
	if tp == 0 {
		t.Fatal("no labelled issues evaluated")
	}
	if sum.PolicyBundleSHA256 == "" || sum.CatalogSHA256 == "" {
		t.Error("run is missing provenance")
	}
	var bundles int
	pool.QueryRow(context.Background(), `SELECT count(*) FROM policy_bundles WHERE sha256 = $1 AND jsonb_typeof(modules) = 'object'`, sum.PolicyBundleSHA256).Scan(&bundles)
	if bundles != 1 {
		t.Error("policy bundle text not stored; result would not be reproducible")
	}
}

func TestCoverageAndStaleness(t *testing.T) {
	_, svc, _ := complianceSvc(t)
	ctx := context.Background()
	if _, err := svc.EvaluateInventory(ctx, "demo", "tester"); err != nil {
		t.Fatal(err)
	}
	cov, err := svc.Coverage(ctx, "demo", "nist-csf-2.0", compliance.ScopeObserved, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]compliance.ControlStatus{}
	for _, c := range cov.Controls {
		status[c.ControlID] = c
	}
	if status["PR.DS-01"].Status != "failing" || status["PR.DS-01"].Fail == 0 {
		t.Errorf("PR.DS-01: %+v", status["PR.DS-01"])
	}
	if status["DE.CM-09"].Status != "not_covered" || status["PR.AA-01"].Status != "not_covered" {
		t.Error("unmapped controls must be reported as not_covered, not passing")
	}
	if status["PR.DS-01"].Stale {
		t.Error("fresh evidence reported stale")
	}
	if cov.Summary["total"] != 9 || cov.Summary["not_covered"] != 2 {
		t.Errorf("summary %v", cov.Summary)
	}

	planned, err := svc.Coverage(ctx, "demo", "nist-csf-2.0", compliance.ScopePlanned, time.Hour)
	if err != nil || len(planned.Controls) == 0 {
		t.Fatalf("planned coverage: %d controls, %v", len(planned.Controls), err)
	}
	for _, c := range planned.Controls {
		if c.Status != "no_evidence" && c.Status != "not_covered" {
			t.Errorf("no IaC evaluations yet, but %s is %s", c.ControlID, c.Status)
		}
	}
	time.Sleep(5 * time.Millisecond)
	stale, _ := svc.Coverage(ctx, "demo", "nist-csf-2.0", compliance.ScopeObserved, time.Millisecond)
	if stale.Summary["stale"] == 0 {
		t.Error("old evidence not flagged stale")
	}
	if _, err := svc.Coverage(ctx, "demo", "iso-27001", compliance.ScopeObserved, time.Hour); !errors.Is(err, compliance.ErrNotFound) {
		t.Errorf("unknown framework: %v", err)
	}

	cis, _ := svc.Control(ctx, "demo", "cis-aws-foundations-3.0.0", "2.1.4", compliance.ScopeObserved, time.Hour)
	if len(cis.Evaluations) == 0 || cis.Evaluations[0].Result != compliance.ResultFail || cis.Evaluations[0].Evidence["content_sha256"] == nil {
		t.Errorf("control detail must list failing evidence first with a snapshot pointer: %+v", cis.Evaluations[:min(1, len(cis.Evaluations))])
	}
	if len(cis.History) == 0 || cis.Remediation["AEGIS-S3-001"] == "" {
		t.Error("control detail missing history or remediation")
	}
}

func TestExceptionWorkflowAndAudit(t *testing.T) {
	pool, svc, ds := complianceSvc(t)
	ctx := context.Background()
	var publicBucket string
	for id, issues := range ds.Labels {
		for _, is := range issues {
			if is == synthetic.IssuePublicBucket && (publicBucket == "" || id < publicBucket) {
				publicBucket = id
			}
		}
	}
	expires := time.Now().Add(30 * 24 * time.Hour)

	bad := []compliance.ExceptionRequest{
		{RuleID: "AEGIS-NOPE-001", Subject: "x", Justification: "a long enough justification text", ExpiresAt: expires},
		{RuleID: "AEGIS-NET-001", Subject: "*", Justification: "a long enough justification text", ExpiresAt: expires},
		{RuleID: "AEGIS-S3-001", Subject: publicBucket, Justification: "too short", ExpiresAt: expires},
		{RuleID: "AEGIS-S3-001", Subject: publicBucket, Justification: "a long enough justification text", ExpiresAt: time.Now().Add(400 * 24 * time.Hour)},
		{RuleID: "AEGIS-S3-001", Subject: publicBucket, Justification: "a long enough justification text", ExpiresAt: time.Now().Add(-time.Hour)},
	}
	for i, req := range bad {
		if _, err := svc.RequestException(ctx, "demo", "alice", req); !errors.Is(err, compliance.ErrInvalid) {
			t.Errorf("bad request %d accepted: %v", i, err)
		}
	}

	ex, err := svc.RequestException(ctx, "demo", "alice", compliance.ExceptionRequest{
		RuleID: "AEGIS-S3-001", Subject: publicBucket, ExpiresAt: expires,
		Justification: "Public static website bucket; contains only public marketing assets."})
	if err != nil || ex.Status != "requested" || ex.Active {
		t.Fatalf("request: %+v %v", ex, err)
	}
	if _, err := svc.DecideException(ctx, "demo", "alice", ex.ID, compliance.DecisionApprove); !errors.Is(err, compliance.ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	ex, err = svc.DecideException(ctx, "demo", "bob", ex.ID, compliance.DecisionApprove)
	if err != nil || ex.Status != "approved" || !ex.Active || ex.DecidedBy != "bob" {
		t.Fatalf("approve: %+v %v", ex, err)
	}
	if _, err := svc.DecideException(ctx, "demo", "carol", ex.ID, compliance.DecisionApprove); !errors.Is(err, compliance.ErrConflict) {
		t.Fatalf("double approve: %v", err)
	}

	sum, err := svc.EvaluateInventory(ctx, "demo", "tester")
	if err != nil {
		t.Fatal(err)
	}
	e := runEvals(t, pool, sum.RunID)[[2]string{"AEGIS-S3-001", publicBucket}]
	if e.result != compliance.ResultExcepted || e.exception != ex.ID {
		t.Fatalf("exception not applied: %+v", e)
	}

	if _, err := svc.DecideException(ctx, "demo", "carol", ex.ID, compliance.DecisionRevoke); err != nil {
		t.Fatal(err)
	}
	sum, _ = svc.EvaluateInventory(ctx, "demo", "tester")
	if e := runEvals(t, pool, sum.RunID)[[2]string{"AEGIS-S3-001", publicBucket}]; e.result != compliance.ResultFail {
		t.Fatalf("revoked exception still applied: %+v", e)
	}

	// The audit trail records every step, including the refused self-approval.
	recs, _ := svc.AuditEvents(ctx, "demo", 100, 0)
	seen := map[string]int{}
	for _, r := range recs {
		seen[r.Action+"/"+r.Outcome]++
	}
	for _, want := range []string{"exception.request/success", "exception.approve/denied", "exception.approve/success",
		"exception.revoke/success", "compliance.evaluate/success"} {
		if seen[want] == 0 {
			t.Errorf("audit missing %s (have %v)", want, seen)
		}
	}
	if v, err := svc.VerifyAudit(ctx, "demo"); err != nil || !v.Valid || v.Checked < 5 {
		t.Fatalf("audit verify: %+v %v", v, err)
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	pool, svc, _ := complianceSvc(t)
	ctx := context.Background()
	var tenantID string
	pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'demo'`).Scan(&tenantID)

	// Concurrent appends must produce one gap-free, valid chain (after the
	// events already recorded, such as the inventory import).
	before, err := svc.VerifyAudit(ctx, "demo")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
				return audit.Append(ctx, tx, tenantID, audit.Event{Actor: "w", Action: "test.event", TargetType: "t",
					TargetID: fmt.Sprint(i), Outcome: "success", Details: map[string]any{"n": i, "nested": map[string]any{"b": 1, "a": 2.5}}})
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	v, err := svc.VerifyAudit(ctx, "demo")
	if err != nil || !v.Valid || v.Checked != before.Checked+20 {
		t.Fatalf("concurrent chain: %+v %v", v, err)
	}

	// The append-only trigger blocks edits; a table owner can still disable it,
	// which is exactly the case the hash chain exists to detect.
	if _, err := pool.Exec(ctx, `UPDATE audit_events SET actor = 'mallory' WHERE seq = 7`); err == nil {
		t.Fatal("append-only trigger did not block the update")
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only;
		UPDATE audit_events SET actor = 'mallory' WHERE tenant_id = '`+tenantID+`' AND seq = 7;
		ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only;`); err != nil {
		t.Fatal(err)
	}
	v, _ = svc.VerifyAudit(ctx, "demo")
	if v.Valid || v.FirstBadSeq != 7 {
		t.Fatalf("tampering not detected at seq 7: %+v", v)
	}
}

// Every hashed column is covered, and so are a deleted event and a broken
// link: a digest that silently drops a field would pass the single-column
// tamper check above.
func TestAuditChainDetectsEveryKindOfTampering(t *testing.T) {
	cases := map[string]struct {
		sql     string
		firstAt int64
	}{
		"details":     {`UPDATE audit_events SET details = '{"role":"admin"}' WHERE tenant_id = $1 AND seq = 5`, 5},
		"outcome":     {`UPDATE audit_events SET outcome = 'failure' WHERE tenant_id = $1 AND seq = 5`, 5},
		"target_id":   {`UPDATE audit_events SET target_id = 'other' WHERE tenant_id = $1 AND seq = 5`, 5},
		"occurred_at": {`UPDATE audit_events SET occurred_at = occurred_at - interval '1 day' WHERE tenant_id = $1 AND seq = 5`, 5},
		"action":      {`UPDATE audit_events SET action = 'test.other' WHERE tenant_id = $1 AND seq = 5`, 5},
		"prev_hash":   {`UPDATE audit_events SET prev_hash = hash WHERE tenant_id = $1 AND seq = 5`, 5},
		"deleted":     {`DELETE FROM audit_events WHERE tenant_id = $1 AND seq = 5`, 6}, // the gap shows at the next event
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			pool, svc, _ := complianceSvc(t)
			ctx := context.Background()
			var tenantID string
			if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'demo'`).Scan(&tenantID); err != nil {
				t.Fatal(err)
			}
			for i := range 8 {
				if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
					return audit.Append(ctx, tx, tenantID, audit.Event{Actor: "w", Action: "test.event", TargetType: "t",
						TargetID: fmt.Sprint(i), Outcome: "success", Details: map[string]any{"role": "viewer", "n": i}})
				}); err != nil {
					t.Fatal(err)
				}
			}
			if v, err := svc.VerifyAudit(ctx, "demo"); err != nil || !v.Valid {
				t.Fatalf("chain before tampering: %+v %v", v, err)
			}
			if _, err := pool.Exec(ctx, `ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only`); err != nil {
				t.Fatal(err)
			}
			_, err := pool.Exec(ctx, c.sql, tenantID)
			if _, e := pool.Exec(ctx, `ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only`); e != nil {
				t.Fatal(e)
			}
			if err != nil {
				t.Fatal(err)
			}
			v, err := svc.VerifyAudit(ctx, "demo")
			if err != nil || v.Valid || v.FirstBadSeq != c.firstAt {
				t.Fatalf("tampered %s not detected at seq %d: %+v %v", name, c.firstAt, v, err)
			}
		})
	}
}

func TestEvaluateScanEvidence(t *testing.T) {
	pool, svc, _ := complianceSvc(t)
	ctx := context.Background()
	store := iac.NewStore(pool)
	scan, _, _ := store.Enqueue(ctx, "demo", "tester", "insecure-storage", "")

	if _, err := svc.EvaluateScan(ctx, "demo", scan.ID, "tester"); !errors.Is(err, compliance.ErrScanNotReady) {
		t.Fatalf("queued scan evaluated: %v", err)
	}
	j, _ := store.Claim(ctx, "w", time.Minute)
	bundle := opa.Bundle{SHA256: fmt.Sprintf("%064x", 7), Modules: map[string]string{"/policies/x.rego": "package x"}}
	err := store.Complete(ctx, j, "w", iac.Result{
		Analysis: iac.Analysis{Resources: []iac.PlannedResource{
			{Address: "aws_db_instance.old", Type: "aws_db_instance", Action: iac.ActionDelete, Destructive: true},
			{Address: "aws_s3_bucket.b", Type: "aws_s3_bucket", Action: iac.ActionCreate, Taggable: true, Region: "ap-south-1",
				After: map[string]any{"bucket": "b"}},
		}},
		Findings: iac.Merge([]iac.Finding{
			{Source: iac.SourcePolicy, RuleID: "AEGIS-TF-001", Severity: "high", Decision: "deny", ResourceAddress: "aws_db_instance.old"},
			{Source: iac.SourcePolicy, RuleID: "AEGIS-S3-001", Severity: "high", Decision: "deny", ResourceAddress: "aws_s3_bucket.b"},
			{Source: iac.SourceTrivy, RuleID: "AVD-AWS-0086", Severity: "high", Decision: "fail", ResourceAddress: "aws_s3_bucket.b"},
		}),
		PolicyBundleSHA256: bundle.SHA256, PolicyBundle: bundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := svc.EvaluateScan(ctx, "demo", scan.ID, "tester")
	if err != nil {
		t.Fatal(err)
	}
	evs := runEvals(t, pool, sum.RunID)
	if evs[[2]string{"AEGIS-TF-001", "aws_db_instance.old"}].result != compliance.ResultFail ||
		evs[[2]string{"AEGIS-S3-001", "aws_s3_bucket.b"}].result != compliance.ResultFail ||
		evs[[2]string{"AEGIS-ENC-001", "aws_s3_bucket.b"}].result != compliance.ResultPass {
		t.Fatalf("scan evaluations: %+v", evs)
	}
	if _, ok := evs[[2]string{"AEGIS-DB-001", "aws_db_instance.old"}]; ok {
		t.Error("configuration rules must not apply to a resource being deleted")
	}
	for k := range evs {
		if k[0] == "AVD-AWS-0086" {
			t.Error("third-party scanner findings must not become compliance evaluations")
		}
	}
	if sum.PolicyBundleSHA256 != bundle.SHA256 || sum.SourceKey != "insecure-storage" {
		t.Errorf("provenance: %+v", sum)
	}
}

func TestPolicyEngineOutageRecordsNothing(t *testing.T) {
	pool, svc, _ := complianceSvc(t)
	svc.OPA = &opa.Client{BaseURL: "http://127.0.0.1:1"}
	_, err := svc.EvaluateInventory(context.Background(), "demo", "tester")
	var u *opa.UnavailableError
	if !errors.As(err, &u) {
		t.Fatalf("want UnavailableError, got %v", err)
	}
	var n int
	pool.QueryRow(context.Background(), `SELECT count(*) FROM compliance_runs`).Scan(&n)
	if n != 0 {
		t.Fatal("a run was recorded although the policy engine was down")
	}
}
