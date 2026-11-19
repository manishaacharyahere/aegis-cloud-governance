package integration

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/tenancy"
)

// Per-tenant policy settings change what the policies judge, for this tenant only.
func TestTenantPolicyConfig(t *testing.T) {
	opaURL := os.Getenv("AEGIS_TEST_OPA_URL")
	if opaURL == "" {
		t.Skip("AEGIS_TEST_OPA_URL not set")
	}
	pool, inv := migratedPool(t)
	ctx := context.Background()
	snap := inventory.Snapshot{SchemaVersion: inventory.SchemaV1, Source: "synthetic", CapturedAt: base,
		Account: inventory.Account{Provider: "aws", ExternalID: "123456789012", Name: "demo"},
		Resources: []inventory.Resource{{ResourceID: "aws_s3_bucket.eu", ResourceType: "aws_s3_bucket", Region: "eu-west-1",
			Tags:          map[string]string{"owner": "a", "environment": "dev", "cost_center": "c"},
			Configuration: map[string]any{"public_access_block": true, "versioning": true, "encryption": "aws:kms"}}}}
	for _, tenant := range []string{"demo", "other"} {
		if _, err := inv.Import(ctx, tenant, "tester", snap); err != nil {
			t.Fatal(err)
		}
	}
	cat, _ := compliance.LoadCatalog()
	csvc := &compliance.Service{Pool: pool, Catalog: cat, OPA: testOPA(opaURL)}
	regionFails := func(tenant string) int {
		if _, err := csvc.EvaluateInventory(ctx, tenant, "tester"); err != nil {
			t.Fatal(err)
		}
		return count(t, pool, `SELECT count(*) FROM compliance_evaluations e JOIN compliance_runs r ON r.id = e.run_id
			JOIN tenants t ON t.id = r.tenant_id WHERE t.slug = $1 AND e.rule_id = 'AEGIS-REG-001' AND e.result = 'fail'
			AND r.evaluated_at = (SELECT max(evaluated_at) FROM compliance_runs WHERE tenant_id = t.id)`, tenant)
	}
	if n := regionFails("demo"); n != 0 {
		t.Fatalf("eu-west-1 is approved by default, got %d failures", n)
	}

	store := &tenancy.Store{Pool: pool}
	if err := store.Put(ctx, "demo", "admin@example.com", tenancy.PolicyConfig{ApprovedRegions: []string{"us-east-1"}, AdminPorts: []int{22, 3389, 5985}}); err != nil {
		t.Fatal(err)
	}
	if n := regionFails("demo"); n != 1 {
		t.Errorf("after restricting regions, demo has %d region failures, want 1", n)
	}
	if n := regionFails("other"); n != 0 {
		t.Errorf("another tenant's settings leaked: %d", n)
	}
	if err := store.Put(ctx, "demo", "admin@example.com", tenancy.PolicyConfig{ApprovedRegions: []string{"Mars-1"}, AdminPorts: []int{70000}}); !errors.Is(err, tenancy.ErrInvalid) {
		t.Errorf("invalid config accepted: %v", err)
	}
	if n := count(t, pool, `SELECT count(*) FROM audit_events WHERE action = 'tenant.policy_config.updated'`); n != 1 {
		t.Errorf("audit events = %d", n)
	}
}
