package finops

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const header = "usage_date,account_id,service,resource_id,usage_type,cost_usd,currency,tag_team,tag_environment,tag_cost_center,cpu_utilization\n"

func TestParseCSVValid(t *testing.T) {
	csv := header +
		"2025-01-01,123456789012,AmazonEC2,aws_instance.a,BoxUsage:t3.medium,1.5,USD,payments,production,payments,42.5\n" +
		"2025-01-01,123456789012,AWSDataTransfer,,DataTransfer-Out-Bytes,30,USD,,,,\n"
	recs, err := ParseCSV(strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].CPU == nil || *recs[0].CPU != 42.5 || recs[1].CPU != nil || recs[0].TagTeam != "payments" {
		t.Fatalf("parsed: %+v", recs)
	}
	// Column order does not matter; BOM tolerated.
	re := "\ufeffcurrency,cost_usd,usage_type,resource_id,service,account_id,usage_date\nUSD,2,x,r,S,123456789012,2025-02-01\n"
	if recs, err := ParseCSV(strings.NewReader(re)); err != nil || recs[0].CostUSD != 2 {
		t.Fatalf("reordered: %v %+v", err, recs)
	}
}

func TestParseCSVRejects(t *testing.T) {
	row := func(date, acct, cost, cur, cpu string) string {
		return header + date + "," + acct + ",S,r,u," + cost + "," + cur + ",,,," + cpu + "\n"
	}
	cases := map[string]struct{ csv, col string }{
		"bad date":     {row("2025-13-01", "123456789012", "1", "USD", ""), "usage_date"},
		"bad account":  {row("2025-01-01", "12345", "1", "USD", ""), "account_id"},
		"not a number": {row("2025-01-01", "123456789012", "abc", "USD", ""), "cost_usd"},
		"NaN":          {row("2025-01-01", "123456789012", "NaN", "USD", ""), "cost_usd"},
		"negative":     {row("2025-01-01", "123456789012", "-5", "USD", ""), "cost_usd"},
		"currency":     {row("2025-01-01", "123456789012", "1", "EUR", ""), "currency"},
		"cpu range":    {row("2025-01-01", "123456789012", "1", "USD", "140"), "cpu_utilization"},
		"missing col":  {"usage_date,account_id\n2025-01-01,123456789012\n", "service"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseCSV(strings.NewReader(c.csv))
			var v *ValidationError
			if !errors.As(err, &v) || v.Errors[0].Column != c.col {
				t.Fatalf("want error on %s, got %v", c.col, err)
			}
		})
	}
	dup := header + "2025-01-01,123456789012,S,r,u,1,USD,,,,\n2025-01-01,123456789012,S,r,u,2,USD,,,,\n"
	if _, err := ParseCSV(strings.NewReader(dup)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate key accepted: %v", err)
	}
	if _, err := ParseCSV(strings.NewReader(header)); err == nil {
		t.Error("empty file accepted")
	}
}

func TestParseCSVCapsErrors(t *testing.T) {
	var b strings.Builder
	b.WriteString(header)
	for range 200 {
		b.WriteString("bad,bad,S,r,u,1,USD,,,,\n")
	}
	_, err := ParseCSV(strings.NewReader(b.String()))
	var v *ValidationError
	if !errors.As(err, &v) || len(v.Errors) != maxReportedErrs || !v.Truncated {
		t.Fatalf("errors not capped: %v", err)
	}
}

func TestAllocatePrecedence(t *testing.T) {
	recs := []Record{
		{ResourceID: "a", TagTeam: "payments", TagEnv: "production"},
		{ResourceID: "b", CostCenter: "search"},
		{ResourceID: "c"},
		{ResourceID: "d"},
		{ResourceID: ""},
	}
	Allocate(recs, map[string]Owner{"a": {"ignored", "x"}, "c": {"platform", "staging"}})
	want := []struct{ team, method, env string }{
		{"payments", "row_tag", "production"}, {"search", "row_tag", ""}, {"platform", "inventory_tag", "staging"},
		{"", "unallocated", ""}, {"", "unallocated", ""},
	}
	for i, w := range want {
		if recs[i].Team != w.team || recs[i].Method != w.method || recs[i].Environment != w.env {
			t.Errorf("rec %d: %+v, want %+v", i, recs[i], w)
		}
	}
}

func days(n int, cost float64, cpu float64, weekendCost float64) []Day {
	start := time.Date(2025, 3, 3, 0, 0, 0, 0, time.UTC) // a Monday
	out := make([]Day, n)
	for i := range n {
		d := start.AddDate(0, 0, i)
		c := cost
		if d.Weekday() == time.Saturday || d.Weekday() == time.Sunday {
			c = weekendCost
		}
		v := cpu
		out[i] = Day{Date: d, Cost: c, CPU: &v}
	}
	return out
}

func TestRecommendRules(t *testing.T) {
	usages := []ResourceUsage{
		{ResourceID: "idle", Service: "AmazonEC2", UsageType: "BoxUsage:m6i.large", Team: "t", Environment: "production", Days: days(14, 2.304, 1, 2.304)},
		{ResourceID: "big", Service: "AmazonEC2", UsageType: "BoxUsage:m6i.4xlarge", Team: "t", Environment: "production", Days: days(14, 18.432, 10, 18.432)},
		{ResourceID: "smallest", Service: "AmazonEC2", UsageType: "BoxUsage:t3.micro", Team: "t", Environment: "production", Days: days(14, 0.25, 10, 0.25)},
		{ResourceID: "dev-24x7", Service: "AmazonEC2", UsageType: "BoxUsage:t3.medium", Team: "t", Environment: "development", Days: days(14, 1, 50, 1)},
		{ResourceID: "dev-off", Service: "AmazonEC2", UsageType: "BoxUsage:t3.medium", Team: "t", Environment: "development", Days: days(14, 1, 50, 0.05)},
		{ResourceID: "prod-busy", Service: "AmazonEC2", UsageType: "BoxUsage:t3.medium", Team: "t", Environment: "production", Days: days(14, 1, 60, 1)},
		{ResourceID: "orphan", Service: "AmazonS3", UsageType: "TimedStorage", Days: days(14, 3, 0, 3)},
		{ResourceID: "new", Service: "AmazonEC2", UsageType: "BoxUsage:m6i.large", Team: "t", Days: days(3, 2, 1, 2)},
	}
	got := map[string]Recommendation{}
	for _, r := range Recommend(usages) {
		got[r.ResourceID+"/"+r.Kind] = r
	}
	if r, ok := got["idle/idle"]; !ok || r.ProjectedMonthly != 69.12 {
		t.Errorf("idle: %+v", r)
	}
	big := got["big/rightsizing"]
	if big.Details["to"] != "c6i.xlarge" || big.ProjectedMonthly != round2(18.432*30*(1-0.17/0.768)) {
		t.Errorf("rightsizing: %+v", big)
	}
	if _, ok := got["smallest/rightsizing"]; ok {
		t.Error("no smaller size exists for t3.micro")
	}
	if _, ok := got["dev-24x7/schedule_non_prod"]; !ok {
		t.Error("non-prod instance running at weekends not flagged")
	}
	for _, k := range []string{"dev-off/schedule_non_prod", "prod-busy/schedule_non_prod", "new/idle"} {
		if _, ok := got[k]; ok {
			t.Errorf("unexpected %s", k)
		}
	}
	if r, ok := got["orphan/allocation"]; !ok || r.ProjectedMonthly != 0 {
		t.Errorf("unallocated spend: %+v", r)
	}
	if _, ok := got["idle/rightsizing"]; ok {
		t.Error("an idle instance must not also get a rightsizing recommendation")
	}
	recs := Recommend(usages)
	for i := 1; i < len(recs); i++ {
		if recs[i].ProjectedMonthly > recs[i-1].ProjectedMonthly {
			t.Fatal("recommendations not sorted by projected savings")
		}
	}
}

func TestP95(t *testing.T) {
	xs := make([]float64, 100)
	for i := range xs {
		xs[i] = float64(i + 1)
	}
	if p95(xs) != 95 || p95([]float64{7}) != 7 {
		t.Errorf("p95 = %v", p95(xs))
	}
}

func TestParseCSVStripsByteOrderMark(t *testing.T) {
	bom := string([]byte{0xEF, 0xBB, 0xBF})
	csv := bom + "usage_date,account_id,service,resource_id,usage_type,cost_usd,currency\n2025-01-01,123456789012,S,r,u,1,USD\n"
	if _, err := ParseCSV(strings.NewReader(csv)); err != nil {
		t.Fatalf("file with a UTF-8 BOM rejected: %v", err)
	}
}
