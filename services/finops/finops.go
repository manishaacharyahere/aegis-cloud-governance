// Package finops implements Module F (FinOps intelligence) on the Go side:
// cost import and validation, tag-based allocation, cost reporting and
// rule-based optimisation recommendations. Statistical forecasting and
// anomaly detection live in the Python package (ml/aegis_ml) and write
// their results to PostgreSQL, which this package serves.
package finops

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Required CSV columns (order-independent).
var requiredColumns = []string{"usage_date", "account_id", "service", "resource_id", "usage_type", "cost_usd", "currency"}

// Optional columns.
var optionalColumns = []string{"tag_team", "tag_environment", "tag_cost_center", "cpu_utilization"}

// Limits.
const (
	MaxRows         = 2_000_000
	maxReportedErrs = 50
)

var accountRe = regexp.MustCompile(`^[0-9]{12}$`)

// Record is one validated cost line.
type Record struct {
	UsageDate   time.Time
	AccountID   string
	Service     string
	ResourceID  string
	UsageType   string
	CostUSD     float64
	TagTeam     string
	TagEnv      string
	CostCenter  string
	CPU         *float64
	Team        string // after allocation
	Environment string
	Method      string // row_tag | inventory_tag | unallocated
}

// RowError locates a validation problem.
type RowError struct {
	Line    int    `json:"line"`
	Column  string `json:"column"`
	Message string `json:"message"`
}

// ValidationError is returned when any row is invalid; nothing is imported.
type ValidationError struct {
	Errors    []RowError `json:"errors"`
	Truncated bool       `json:"truncated"`
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("cost data failed validation (%d problems, first: line %d %s: %s)",
		len(e.Errors), e.Errors[0].Line, e.Errors[0].Column, e.Errors[0].Message)
}

// ParseCSV validates a CUR-like CSV. It is all-or-nothing: one bad row
// rejects the file, so partial imports never distort reports.
func ParseCSV(r io.Reader) ([]Record, error) {
	cr := csv.NewReader(r)
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.TrimSpace(strings.ToLower(strings.TrimPrefix(h, "\ufeff")))] = i
	}
	verr := &ValidationError{}
	add := func(line int, c, msg string) {
		if len(verr.Errors) >= maxReportedErrs {
			verr.Truncated = true
			return
		}
		verr.Errors = append(verr.Errors, RowError{line, c, msg})
	}
	for _, c := range requiredColumns {
		if _, ok := col[c]; !ok {
			add(1, c, "required column missing")
		}
	}
	if len(verr.Errors) > 0 {
		return nil, verr
	}
	get := func(row []string, c string) string {
		if i, ok := col[c]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}

	var out []Record
	line := 1
	for {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		line++
		if err != nil {
			add(line, "", "malformed CSV: "+err.Error())
			break
		}
		if len(out) >= MaxRows {
			add(line, "", fmt.Sprintf("too many rows (max %d)", MaxRows))
			break
		}
		rec := Record{AccountID: get(row, "account_id"), Service: get(row, "service"), ResourceID: get(row, "resource_id"),
			UsageType: get(row, "usage_type"), TagTeam: get(row, "tag_team"), TagEnv: get(row, "tag_environment"),
			CostCenter: get(row, "tag_cost_center")}
		d, err := time.Parse("2006-01-02", get(row, "usage_date"))
		if err != nil {
			add(line, "usage_date", "must be YYYY-MM-DD")
		}
		rec.UsageDate = d
		if !accountRe.MatchString(rec.AccountID) {
			add(line, "account_id", "must be a 12-digit account ID")
		}
		if rec.Service == "" || len(rec.Service) > 100 {
			add(line, "service", "required, at most 100 characters")
		}
		if rec.UsageType == "" || len(rec.UsageType) > 200 {
			add(line, "usage_type", "required, at most 200 characters")
		}
		if len(rec.ResourceID) > 512 {
			add(line, "resource_id", "longer than 512 characters")
		}
		cost, err := strconv.ParseFloat(get(row, "cost_usd"), 64)
		switch {
		case err != nil || math.IsNaN(cost) || math.IsInf(cost, 0):
			add(line, "cost_usd", "must be a number")
		case cost < 0:
			add(line, "cost_usd", "negative costs (credits/refunds) are not supported yet")
		case cost >= 1e10:
			add(line, "cost_usd", "implausibly large")
		}
		rec.CostUSD = cost
		if cur := get(row, "currency"); cur != "USD" {
			add(line, "currency", fmt.Sprintf("only USD is supported, got %q", cur))
		}
		if v := get(row, "cpu_utilization"); v != "" {
			cpu, err := strconv.ParseFloat(v, 64)
			if err != nil || cpu < 0 || cpu > 100 {
				add(line, "cpu_utilization", "must be between 0 and 100")
			} else {
				rec.CPU = &cpu
			}
		}
		out = append(out, rec)
	}
	if len(verr.Errors) > 0 {
		return nil, verr
	}
	if len(out) == 0 {
		return nil, &ValidationError{Errors: []RowError{{Line: 2, Message: "no data rows"}}}
	}
	// Duplicate keys inside one file are ambiguous.
	seen := make(map[string]int, len(out))
	for i, r := range out {
		k := r.UsageDate.Format("2006-01-02") + "|" + r.AccountID + "|" + r.ResourceID + "|" + r.UsageType
		if prev, dup := seen[k]; dup {
			return nil, &ValidationError{Errors: []RowError{{Line: i + 2, Message: fmt.Sprintf("duplicate of line %d (same date, account, resource, usage type)", prev+2)}}}
		}
		seen[k] = i
	}
	return out, nil
}

// Owner is the inventory's view of who owns a resource.
type Owner struct{ Team, Environment string }

// Allocate assigns every record to a team with this precedence:
// 1) the row's own team / cost-centre tag, 2) the inventory resource's
// cost_center tag, 3) unallocated. The method is recorded per row.
func Allocate(recs []Record, inventory map[string]Owner) {
	for i := range recs {
		r := &recs[i]
		team := r.TagTeam
		if team == "" {
			team = r.CostCenter
		}
		switch {
		case team != "":
			r.Team, r.Environment, r.Method = team, r.TagEnv, "row_tag"
		case r.ResourceID != "" && inventory[r.ResourceID].Team != "":
			o := inventory[r.ResourceID]
			r.Team, r.Environment, r.Method = o.Team, o.Environment, "inventory_tag"
		default:
			r.Team, r.Environment, r.Method = "", r.TagEnv, "unallocated"
		}
		if r.Environment == "" && inventory[r.ResourceID].Environment != "" {
			r.Environment = inventory[r.ResourceID].Environment
		}
	}
}

// ------------------------------------------------------------ recommendations

// HourlyPrice are illustrative on-demand list prices (USD, Linux, us-east-1
// style), used as planning assumptions only. Keep in sync with ml/aegis_ml/costgen.py.
var HourlyPrice = map[string]float64{
	"t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416, "m6i.large": 0.096,
	"c6i.xlarge": 0.17, "m6i.4xlarge": 0.768, "c6i.8xlarge": 1.36,
	"db.t3.micro": 0.017, "db.t3.medium": 0.068,
}

// Smaller is the next size down for rightsizing.
var Smaller = map[string]string{
	"t3.small": "t3.micro", "t3.medium": "t3.small", "m6i.large": "t3.medium", "c6i.xlarge": "m6i.large",
	"m6i.4xlarge": "c6i.xlarge", "c6i.8xlarge": "m6i.4xlarge", "db.t3.medium": "db.t3.micro",
}

// Thresholds for the rules (documented in docs/modules/finops.md).
const (
	WindowDays         = 14
	IdleCPUP95         = 3.0
	RightsizeCPUP95    = 20.0
	WeekendRunningFrac = 0.5
	daysPerMonth       = 30.0
	weekendDaysMonth   = 30.0 * 2 / 7
)

// Day is one day of a resource's cost and utilisation.
type Day struct {
	Date time.Time
	Cost float64
	CPU  *float64
}

// ResourceUsage is the input to the recommendation rules.
type ResourceUsage struct {
	ResourceID  string
	Service     string
	UsageType   string
	Team        string
	Environment string
	Days        []Day
}

// Recommendation is a proposed optimisation. Savings are PROJECTED from
// recent cost and illustrative prices; they are not measured savings.
type Recommendation struct {
	Kind             string         `json:"kind"`
	ResourceID       string         `json:"resource_id"`
	Team             string         `json:"team"`
	Details          map[string]any `json:"details"`
	ProjectedMonthly float64        `json:"projected_monthly_savings"`
}

func p95(xs []float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	idx := int(math.Ceil(0.95*float64(len(s)))) - 1
	return s[max(0, idx)]
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// Recommend applies the rules to resources with at least 7 days of data in
// the window. Each resource gets at most one compute recommendation, in the
// order idle > rightsizing > schedule_non_prod.
func Recommend(usages []ResourceUsage) []Recommendation {
	var out []Recommendation
	for _, u := range usages {
		if len(u.Days) < 7 {
			continue
		}
		var total, weekday, weekend float64
		var nWeekday, nWeekend int
		var cpus []float64
		for _, d := range u.Days {
			total += d.Cost
			if wd := d.Date.Weekday(); wd == time.Saturday || wd == time.Sunday {
				weekend += d.Cost
				nWeekend++
			} else {
				weekday += d.Cost
				nWeekday++
			}
			if d.CPU != nil {
				cpus = append(cpus, *d.CPU)
			}
		}
		avg := total / float64(len(u.Days))
		size := ""
		if i := strings.LastIndex(u.UsageType, ":"); i >= 0 {
			size = u.UsageType[i+1:]
		}
		if u.Team == "" && u.ResourceID != "" && avg > 0 {
			out = append(out, Recommendation{Kind: "allocation", ResourceID: u.ResourceID, Details: map[string]any{
				"reason":         "spend has no owning team (no team tag on the cost line or in the inventory)",
				"avg_daily_cost": round2(avg)}})
		}
		if u.Service != "AmazonEC2" || len(cpus) < 7 {
			continue
		}
		cpuP95 := p95(cpus)
		switch {
		case cpuP95 < IdleCPUP95:
			out = append(out, Recommendation{Kind: "idle", ResourceID: u.ResourceID, Team: u.Team,
				ProjectedMonthly: round2(avg * daysPerMonth), Details: map[string]any{
					"cpu_p95": round2(cpuP95), "avg_daily_cost": round2(avg), "action": "stop or terminate",
					"reason": fmt.Sprintf("p95 CPU %.1f%% < %.0f%% over %d days", cpuP95, IdleCPUP95, len(u.Days))}})
		case cpuP95 < RightsizeCPUP95 && Smaller[size] != "":
			to := Smaller[size]
			ratio := HourlyPrice[to] / HourlyPrice[size]
			out = append(out, Recommendation{Kind: "rightsizing", ResourceID: u.ResourceID, Team: u.Team,
				ProjectedMonthly: round2(avg * daysPerMonth * (1 - ratio)), Details: map[string]any{
					"cpu_p95": round2(cpuP95), "from": size, "to": to, "price_ratio": math.Round(ratio*1000) / 1000,
					"avg_daily_cost": round2(avg),
					"reason":         fmt.Sprintf("p95 CPU %.1f%% < %.0f%%; one size smaller costs %.0f%% less", cpuP95, RightsizeCPUP95, (1-ratio)*100)}})
		case u.Environment != "production" && nWeekend > 0 && nWeekday > 0 &&
			weekend/float64(nWeekend) >= WeekendRunningFrac*weekday/float64(nWeekday):
			wkAvg := weekend / float64(nWeekend)
			out = append(out, Recommendation{Kind: "schedule_non_prod", ResourceID: u.ResourceID, Team: u.Team,
				ProjectedMonthly: round2(wkAvg * weekendDaysMonth * 0.95), Details: map[string]any{
					"environment": u.Environment, "avg_weekend_daily_cost": round2(wkAvg),
					"action": "stop outside working days", "reason": "non-production compute runs at weekends"}})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ProjectedMonthly != out[j].ProjectedMonthly {
			return out[i].ProjectedMonthly > out[j].ProjectedMonthly
		}
		return out[i].ResourceID < out[j].ResourceID
	})
	return out
}
