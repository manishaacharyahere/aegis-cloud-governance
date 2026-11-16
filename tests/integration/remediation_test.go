package integration

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/remediation"
)

// applyToSnapshot plays the role of the cloud: it applies released change
// sets to a copy of the snapshot, as a Terraform pipeline would.
func applyToSnapshot(t *testing.T, snap inventory.Snapshot, at time.Time, changes map[string][][]remediation.Op) inventory.Snapshot {
	t.Helper()
	out := snap
	out.CapturedAt = at
	out.Resources = make([]inventory.Resource, len(snap.Resources))
	copy(out.Resources, snap.Resources)
	for i, r := range out.Resources {
		for _, ops := range changes[r.ResourceID] {
			tags := map[string]any{}
			for k, v := range r.Tags {
				tags[k] = v
			}
			st, _, err := remediation.Apply(remediation.State{Tags: tags, Configuration: r.Configuration}, ops)
			if err != nil {
				t.Fatal(err)
			}
			r.Configuration = st.Configuration
			r.Tags = map[string]string{}
			for k, v := range st.Tags {
				r.Tags[k] = v.(string)
			}
		}
		out.Resources[i] = r
	}
	return out
}

func failingPairs(t *testing.T, pool *pgxpool.Pool) map[[2]string]bool {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT e.rule_id, e.subject FROM compliance_evaluations e
		WHERE e.run_id = (SELECT id FROM compliance_runs WHERE source = 'inventory' ORDER BY evaluated_at DESC, id LIMIT 1)
		AND e.result = 'fail'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[[2]string]bool{}
	for rows.Next() {
		var rule, subj string
		_ = rows.Scan(&rule, &subj)
		out[[2]string{rule, subj}] = true
	}
	return out
}

// TestRemediationClosedLoop proposes a template remediation for every failing
// finding that has one, approves and releases them, applies the released
// change sets to the next snapshot, re-imports, and verifies that exactly
// those findings - and nothing else - changed.
func TestRemediationClosedLoop(t *testing.T) {
	opaURL := os.Getenv("AEGIS_TEST_OPA_URL")
	if opaURL == "" {
		t.Skip("AEGIS_TEST_OPA_URL not set")
	}
	pool, inv := migratedPool(t)
	ctx := context.Background()
	cat, _ := compliance.LoadCatalog()
	oc := &opa.Client{BaseURL: opaURL}
	csvc := &compliance.Service{Pool: pool, Catalog: cat, OPA: oc}
	svc := &remediation.Service{Pool: pool, OPA: oc}

	v1 := synthetic.Generate(synthetic.Options{Seed: 42, Resources: 1000, CapturedAt: base})
	if _, err := inv.Import(ctx, "demo", v1.Snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := csvc.EvaluateInventory(ctx, "demo", "tester"); err != nil {
		t.Fatal(err)
	}
	before := failingPairs(t, pool)

	templated := map[string]bool{}
	for _, tm := range remediation.Templates() {
		templated[tm.RuleID] = true
	}
	approvers := []string{"bob", "carol", "dave"}
	changes := map[string][][]remediation.Op{}
	var released []remediation.View
	fixed := map[[2]string]bool{}
	byRule := map[string]int{}
	for pair := range before {
		rule, subject := pair[0], pair[1]
		if !templated[rule] {
			continue
		}
		v, err := svc.Propose(ctx, "demo", "alice", remediation.ProposeRequest{Source: "finding", RuleID: rule, ResourceID: subject,
			Justification: "close finding from the latest compliance run"})
		if err != nil {
			t.Fatalf("%s on %s: %v", rule, subject, err)
		}
		if v.Status != remediation.StatusPending || !v.Simulation.TargetResolved || len(v.Simulation.Introduced) != 0 {
			t.Fatalf("%s on %s: simulation %+v", rule, subject, v.Simulation)
		}
		for i := 0; i < v.RequiredApprovals; i++ {
			if v, err = svc.Decide(ctx, "demo", approvers[i], v.ID, "approve", "reviewed simulation"); err != nil {
				t.Fatal(err)
			}
			if want := remediation.StatusApproved; (i == v.RequiredApprovals-1) != (v.Status == want) {
				t.Fatalf("after %d of %d approvals status is %s", i+1, v.RequiredApprovals, v.Status)
			}
		}
		if v, err = svc.Release(ctx, "demo", "alice", v.ID); err != nil || v.ChangeSet == nil || v.Status != remediation.StatusReleased {
			t.Fatalf("release: %+v %v", v, err)
		}
		changes[subject] = append(changes[subject], v.ChangeSet.Operations)
		released = append(released, v)
		fixed[pair] = true
		byRule[rule]++
	}
	if len(released) == 0 {
		t.Fatal("no templated findings in the synthetic estate")
	}
	t.Logf("released %d remediations: %v", len(released), byRule)

	// Before the change is observed, verification refuses to guess.
	if _, err := svc.Verify(ctx, "demo", "alice", released[0].ID); !errors.Is(err, remediation.ErrNotObserved) {
		t.Fatalf("verify before re-import: %v", err)
	}

	v2 := applyToSnapshot(t, v1.Snapshot, base.Add(24*time.Hour), changes)
	if _, err := inv.Import(ctx, "demo", v2); err != nil {
		t.Fatal(err)
	}
	for _, r := range released {
		got, err := svc.Verify(ctx, "demo", "alice", r.ID)
		if err != nil || got.Status != remediation.StatusVerified {
			t.Fatalf("verify %s %s: %s %s %v", r.RuleID, r.ResourceID, got.Status, got.Verification, err)
		}
	}
	if _, err := csvc.EvaluateInventory(ctx, "demo", "tester"); err != nil {
		t.Fatal(err)
	}
	after := failingPairs(t, pool)
	for pair := range before {
		if fixed[pair] == after[pair] {
			t.Errorf("%v: remediated=%v but still failing=%v", pair, fixed[pair], after[pair])
		}
	}
	for pair := range after {
		if !before[pair] {
			t.Errorf("%v: new failure after remediation", pair)
		}
	}
	t.Logf("failing findings: %d before, %d after (%d remediated)", len(before), len(after), len(fixed))
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE action LIKE 'remediation.%'`); n < 4*len(released) {
		t.Errorf("audit events = %d for %d remediations", n, len(released))
	}
}

// TestRemediationControls checks the misuse cases: self-approval, double
// approval, blocked plans, forbidden paths, staleness and failed verification.
func TestRemediationControls(t *testing.T) {
	opaURL := os.Getenv("AEGIS_TEST_OPA_URL")
	if opaURL == "" {
		t.Skip("AEGIS_TEST_OPA_URL not set")
	}
	pool, inv := migratedPool(t)
	ctx := context.Background()
	svc := &remediation.Service{Pool: pool, OPA: &opa.Client{BaseURL: opaURL}}
	imports := 0
	bucket := func(pab bool, tags map[string]string) inventory.Snapshot {
		imports++ // each import is a later observation
		return inventory.Snapshot{SchemaVersion: inventory.SchemaV1, Source: "synthetic", CapturedAt: base.Add(time.Duration(imports) * time.Hour),
			Account: inventory.Account{Provider: "aws", ExternalID: "123456789012", Name: "demo"},
			Resources: []inventory.Resource{
				{ResourceID: "aws_s3_bucket.logs", ResourceType: "aws_s3_bucket", Region: "us-east-1", Environment: "development",
					Tags:          tags,
					Configuration: map[string]any{"public_access_block": pab, "versioning": true, "encryption": "aws:kms"}},
				{ResourceID: "aws_iam_policy.admin", ResourceType: "aws_iam_policy", Region: "us-east-1", Environment: "development",
					Tags:          map[string]string{"owner": "a", "environment": "development", "cost_center": "c"},
					Configuration: map[string]any{"statements": []any{map[string]any{"effect": "Allow", "actions": "*", "resources": "*"}}}},
			}}
	}
	tags := map[string]string{"owner": "a", "environment": "development", "cost_center": "c"}
	if _, err := inv.Import(ctx, "demo", bucket(false, tags)); err != nil {
		t.Fatal(err)
	}
	propose := func(req remediation.ProposeRequest) (remediation.View, error) {
		req.Justification = "public bucket found in review"
		return svc.Propose(ctx, "demo", "alice", req)
	}

	for name, req := range map[string]remediation.ProposeRequest{
		"no template":     {Source: "finding", RuleID: "AEGIS-IAM-001", ResourceID: "aws_iam_policy.admin"},
		"forbidden path":  {Source: "manual", ResourceID: "aws_s3_bucket.logs", Operations: []remediation.Op{{Op: "set", Path: "region", Value: "eu-west-1"}}},
		"secret path":     {Source: "manual", ResourceID: "aws_s3_bucket.logs", Operations: []remediation.Op{{Op: "set", Path: "configuration.api_key", Value: "x"}}},
		"ops on template": {Source: "finding", RuleID: "AEGIS-S3-001", ResourceID: "aws_s3_bucket.logs", Operations: []remediation.Op{{Op: "remove", Path: "tags.owner"}}},
	} {
		if _, err := propose(req); !errors.Is(err, remediation.ErrInvalid) && !errors.Is(err, remediation.ErrNoTemplate) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := propose(remediation.ProposeRequest{Source: "finding", RuleID: "AEGIS-S3-002", ResourceID: "aws_s3_bucket.logs"}); !errors.Is(err, remediation.ErrConflict) {
		t.Errorf("rule that is not failing: %v", err)
	}
	if _, err := propose(remediation.ProposeRequest{Source: "finding", RuleID: "AEGIS-S3-001", ResourceID: "aws_s3_bucket.nope"}); !errors.Is(err, remediation.ErrNotFound) {
		t.Errorf("unknown resource: %v", err)
	}

	// A manual change that breaks another control is blocked and cannot be approved.
	blocked, err := propose(remediation.ProposeRequest{Source: "manual", ResourceID: "aws_s3_bucket.logs",
		Operations: []remediation.Op{{Op: "set", Path: "configuration.public_access_block", Value: true}, {Op: "set", Path: "configuration.versioning", Value: false}}})
	if err != nil || blocked.Status != remediation.StatusBlocked || len(blocked.Simulation.Introduced) != 1 {
		t.Fatalf("blocked plan: %+v %v", blocked, err)
	}
	if _, err := svc.Decide(ctx, "demo", "bob", blocked.ID, "approve", ""); !errors.Is(err, remediation.ErrConflict) {
		t.Errorf("approving a blocked plan: %v", err)
	}

	v, err := propose(remediation.ProposeRequest{Source: "finding", RuleID: "AEGIS-S3-001", ResourceID: "aws_s3_bucket.logs"})
	if err != nil || v.Status != remediation.StatusPending || v.RequiredApprovals != 1 {
		t.Fatalf("propose: %+v %v", v, err)
	}
	if _, err := propose(remediation.ProposeRequest{Source: "finding", RuleID: "AEGIS-S3-001", ResourceID: "aws_s3_bucket.logs"}); !errors.Is(err, remediation.ErrConflict) {
		t.Errorf("duplicate open remediation: %v", err)
	}
	if _, err := svc.Release(ctx, "demo", "alice", v.ID); !errors.Is(err, remediation.ErrConflict) {
		t.Errorf("release before approval: %v", err)
	}
	if _, err := svc.Decide(ctx, "demo", "alice", v.ID, "approve", ""); !errors.Is(err, remediation.ErrForbidden) {
		t.Errorf("self-approval: %v", err)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE action = 'remediation.approve' AND outcome = 'denied'`); n != 1 {
		t.Errorf("denied self-approval must be audited, got %d", n)
	}
	if _, err := svc.Get(ctx, "other", v.ID); !errors.Is(err, remediation.ErrNotFound) {
		t.Errorf("cross-tenant read: %v", err)
	}

	// The resource changes before approval: the plan is stale and stays stale.
	tags2 := map[string]string{"owner": "b", "environment": "development", "cost_center": "c"}
	if _, err := inv.Import(ctx, "demo", bucket(false, tags2)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Decide(ctx, "demo", "bob", v.ID, "approve", ""); !errors.Is(err, remediation.ErrStale) {
		t.Fatalf("approving a stale plan: %v", err)
	}
	if got, _ := svc.Get(ctx, "demo", v.ID); got.Status != remediation.StatusStale || len(got.Approvals) != 0 {
		t.Errorf("stale status not persisted: %s, %d approvals", got.Status, len(got.Approvals))
	}

	// Fresh plan, approved and released; the next import does NOT contain the fix.
	v, err = propose(remediation.ProposeRequest{Source: "finding", RuleID: "AEGIS-S3-001", ResourceID: "aws_s3_bucket.logs"})
	if err != nil {
		t.Fatal(err)
	}
	if v, err = svc.Decide(ctx, "demo", "bob", v.ID, "approve", "ok"); err != nil || v.Status != remediation.StatusApproved {
		t.Fatalf("approve: %+v %v", v, err)
	}
	if _, err := svc.Decide(ctx, "demo", "bob", v.ID, "approve", "again"); !errors.Is(err, remediation.ErrConflict) {
		t.Errorf("second decision: %v", err)
	}
	if _, err := svc.Release(ctx, "demo", "carol", v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := inv.Import(ctx, "demo", bucket(false, map[string]string{"owner": "c", "environment": "development", "cost_center": "c"})); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Verify(ctx, "demo", "alice", v.ID)
	if err != nil || got.Status != remediation.StatusVerificationFailed {
		t.Fatalf("verification of an unapplied change: %s %v", got.Status, err)
	}
	// Once the fix is really applied, verification passes on retry.
	if _, err := inv.Import(ctx, "demo", bucket(true, map[string]string{"owner": "c", "environment": "development", "cost_center": "c"})); err != nil {
		t.Fatal(err)
	}
	if got, err = svc.Verify(ctx, "demo", "alice", v.ID); err != nil || got.Status != remediation.StatusVerified {
		t.Fatalf("verification after the fix: %s %s %v", got.Status, got.Verification, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE remediation_approvals SET decision = 'reject'`); err == nil {
		t.Error("approvals must be append-only")
	}
}
