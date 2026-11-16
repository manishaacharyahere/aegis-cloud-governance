package integration

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/finops"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
)

const costHeader = "usage_date,account_id,service,resource_id,usage_type,cost_usd,currency,tag_team,tag_environment,tag_cost_center,cpu_utilization\n"

// costCSV builds 28 days for four resources with known behaviour:
//   - big:    production m6i.4xlarge at 5 % CPU, downsized to c6i.xlarge on day 14
//   - devbox: development t3.medium running every day (weekend waste)
//   - orphan: an S3 bucket with no tags on the cost line; owner known from inventory
//   - shared: data transfer with no resource and no tags (unallocated)
func costCSV(start time.Time, days int, bigCost func(day int) (float64, string)) string {
	var b strings.Builder
	b.WriteString(costHeader)
	for i := range days {
		d := start.AddDate(0, 0, i).Format("2006-01-02")
		c, size := bigCost(i)
		fmt.Fprintf(&b, "%s,123456789012,AmazonEC2,aws_instance.big,BoxUsage:%s,%.4f,USD,payments,production,payments,5\n", d, size, c)
		fmt.Fprintf(&b, "%s,123456789012,AmazonEC2,aws_instance.devbox,BoxUsage:t3.medium,0.9984,USD,search,development,search,40\n", d)
		fmt.Fprintf(&b, "%s,123456789012,AmazonS3,aws_s3_bucket.orphan,TimedStorage-ByteHrs,2.0000,USD,,,,\n", d)
		fmt.Fprintf(&b, "%s,123456789012,AWSDataTransfer,,DataTransfer-Out-Bytes,10.0000,USD,,,,\n", d)
	}
	return b.String()
}

func TestFinOpsLifecycle(t *testing.T) {
	pool, inv := migratedPool(t)
	ctx := context.Background()
	svc := &finops.Service{Pool: pool}

	// Inventory knows the orphan bucket's owner.
	snap := inventory.Snapshot{SchemaVersion: inventory.SchemaV1, Source: "synthetic", CapturedAt: base,
		Account: inventory.Account{Provider: "aws", ExternalID: "123456789012", Name: "demo"},
		Resources: []inventory.Resource{{ResourceID: "aws_s3_bucket.orphan", ResourceType: "aws_s3_bucket",
			Tags: map[string]string{"cost_center": "analytics", "environment": "staging", "owner": "a"}}}}
	if _, err := inv.Import(ctx, "demo", snap); err != nil {
		t.Fatal(err)
	}

	start := time.Date(2025, 3, 3, 0, 0, 0, 0, time.UTC) // Monday
	big := func(day int) (float64, string) {
		if day >= 14 {
			return 0.17 * 24, "c6i.xlarge"
		}
		return 0.768 * 24, "m6i.4xlarge"
	}
	csv := costCSV(start, 28, big)
	res, err := svc.Import(ctx, "demo", "alice", []byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 112 || res.Duplicate || res.From != "2025-03-03" || res.To != "2025-03-30" {
		t.Fatalf("import: %+v", res)
	}
	if got := res.Allocation["inventory_tag"]; math.Abs(got-56) > 0.01 {
		t.Errorf("inventory-tag allocation = %.2f, want 56 (orphan bucket 28 x 2)", got)
	}
	if got := res.Allocation["unallocated"]; math.Abs(got-280) > 0.01 {
		t.Errorf("unallocated = %.2f, want 280 (shared transfer 28 x 10)", got)
	}

	// Same bytes again: idempotent.
	again, err := svc.Import(ctx, "demo", "alice", []byte(csv))
	if err != nil || !again.Duplicate || again.ImportID != res.ImportID {
		t.Fatalf("re-import: %+v %v", again, err)
	}
	// A corrected file for an overlapping day replaces, not duplicates, rows.
	corr := costHeader + "2025-03-03,123456789012,AWSDataTransfer,,DataTransfer-Out-Bytes,15.0000,USD,,,,\n"
	if _, err := svc.Import(ctx, "demo", "alice", []byte(corr)); err != nil {
		t.Fatal(err)
	}
	var n int
	var day1 float64
	pool.QueryRow(ctx, `SELECT count(*), max(cost_usd)::float8 FROM cost_records WHERE usage_date = '2025-03-03' AND service = 'AWSDataTransfer'`).Scan(&n, &day1)
	if n != 1 || day1 != 15 {
		t.Fatalf("correction: %d rows, cost %.2f", n, day1)
	}

	// Invalid file: nothing imported.
	bad := costHeader + "2025-04-01,123456789012,AmazonEC2,x,u,-1,USD,,,,\n"
	var verr *finops.ValidationError
	if _, err := svc.Import(ctx, "demo", "alice", []byte(bad)); !errors.As(err, &verr) {
		t.Fatalf("invalid import: %v", err)
	}

	sum, err := svc.Summarize(ctx, "demo", "team", "", "")
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]float64{}
	for _, g := range sum.Groups {
		keys[g.Key] = g.USD
	}
	if keys["analytics"] != 56 || keys["(unallocated)"] != 285 || sum.Unallocated <= 0 {
		t.Errorf("summary groups %v unallocated %.4f", keys, sum.Unallocated)
	}
	if _, err := svc.Summarize(ctx, "demo", "team; DROP TABLE cost_records", "", ""); !errors.Is(err, finops.ErrInvalid) {
		t.Fatalf("group_by injection not rejected: %v", err)
	}

	// Recommendations as of the day before the downsizing.
	recs, err := svc.GenerateRecommendations(ctx, "demo", "alice", "2025-03-16")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]finops.RecView{}
	for _, r := range recs {
		got[r.ResourceID+"/"+r.Kind] = r
	}
	right, ok := got["aws_instance.big/rightsizing"]
	wantProjected := math.Round(0.768*24*30*(1-0.17/0.768)*100) / 100
	if !ok || right.ProjectedMonthly != wantProjected {
		t.Fatalf("rightsizing: %+v (want projected %.2f)", right, wantProjected)
	}
	if _, ok := got["aws_instance.devbox/schedule_non_prod"]; !ok {
		t.Error("weekend-running dev instance not recommended for scheduling")
	}
	// Regenerating does not duplicate open recommendations.
	again2, _ := svc.GenerateRecommendations(ctx, "demo", "alice", "2025-03-16")
	if len(again2) != len(recs) {
		t.Errorf("regeneration duplicated recommendations: %d vs %d", len(again2), len(recs))
	}

	// Lifecycle: implement requires accept first; measured savings come from data.
	if _, err := svc.DecideRecommendation(ctx, "demo", "bob", right.ID, "implement", "2025-03-17"); !errors.Is(err, finops.ErrConflict) {
		t.Fatalf("implement before accept: %v", err)
	}
	if _, err := svc.DecideRecommendation(ctx, "demo", "bob", right.ID, "accept", ""); err != nil {
		t.Fatal(err)
	}
	done, err := svc.DecideRecommendation(ctx, "demo", "bob", right.ID, "implement", "2025-03-17")
	if err != nil {
		t.Fatal(err)
	}
	if done.MeasuredMonthly == nil {
		t.Fatalf("no measured savings: %+v", done)
	}
	// The real downsizing happened on 2025-03-17 (day 14): 14 days before at m6i.4xlarge, 14 after at c6i.xlarge.
	wantMeasured := math.Round((0.768-0.17)*24*30*100) / 100
	if math.Abs(*done.MeasuredMonthly-wantMeasured) > 0.05 {
		t.Errorf("measured %.2f, want %.2f", *done.MeasuredMonthly, wantMeasured)
	}
	if !strings.Contains(done.MeasurementNote, "simulated") {
		t.Error("measured savings on synthetic data must be labelled as simulated")
	}

	cov, err := svc.TagCoverage(ctx, "demo")
	if err != nil || cov["allocated_share"].(float64) >= 1 {
		t.Fatalf("tag coverage: %v %v", cov, err)
	}

	// ML outputs written by the Python worker are served as stored.
	if _, err := svc.LatestML(ctx, "demo", "forecast", ""); !errors.Is(err, finops.ErrNoData) {
		t.Fatalf("no forecast yet: %v", err)
	}
	var tenantID, runID string
	pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug='demo'`).Scan(&tenantID)
	pool.QueryRow(ctx, `INSERT INTO ml_runs (tenant_id, kind, model, params, data_from, data_to, versions)
		VALUES ($1, 'forecast', 'seasonal_naive', '{"horizon_days":2}', '2025-03-03', '2025-03-30', '{"numpy":"x"}') RETURNING id`, tenantID).Scan(&runID)
	pool.Exec(ctx, `INSERT INTO cost_forecasts VALUES ($1, 'total', '2025-03-31', 100), ($1, 'payments', '2025-03-31', 40)`, runID)
	fc, err := svc.LatestML(ctx, "demo", "forecast", "payments")
	if err != nil || fc.Model != "seasonal_naive" || len(fc.Points) != 1 || fc.Points[0]["predicted_usd"] != 40.0 {
		t.Fatalf("forecast: %+v %v", fc, err)
	}
}
