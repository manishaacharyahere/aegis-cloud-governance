package finops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
)

// Errors.
var (
	ErrTenantNotFound = errors.New("tenant not found")
	ErrNotFound       = errors.New("not found")
	ErrInvalid        = errors.New("invalid request")
	ErrNoData         = errors.New("no cost data")
	ErrConflict       = errors.New("recommendation is not in a state that allows this transition")
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Service is the FinOps module.
type Service struct{ Pool *pgxpool.Pool }

func (s *Service) tenantID(ctx context.Context, slug string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, slug).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTenantNotFound
	}
	return id, err
}

// ImportResult summarises a cost import.
type ImportResult struct {
	ImportID    string             `json:"import_id"`
	Duplicate   bool               `json:"duplicate"`
	Rows        int                `json:"rows"`
	From        string             `json:"from"`
	To          string             `json:"to"`
	TotalUSD    float64            `json:"total_usd"`
	Allocation  map[string]float64 `json:"allocation_usd"` // by method
	Unallocated float64            `json:"unallocated_share"`
	SHA256      string             `json:"sha256"`
}

// Import validates, allocates and upserts a cost CSV. Re-importing the same
// bytes returns the earlier import; corrected rows for the same key replace
// the old ones.
func (s *Service) Import(ctx context.Context, tenant, actor string, raw []byte) (ImportResult, error) {
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return ImportResult{}, err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	var existing ImportResult
	err = s.Pool.QueryRow(ctx, `SELECT id, rows, from_date::text, to_date::text, total_usd::float8 FROM cost_imports
		WHERE tenant_id = $1 AND sha256 = $2`, tenantID, digest).Scan(&existing.ImportID, &existing.Rows, &existing.From, &existing.To, &existing.TotalUSD)
	if err == nil {
		existing.Duplicate, existing.SHA256 = true, digest
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return ImportResult{}, err
	}

	recs, err := ParseCSV(bytes.NewReader(raw))
	if err != nil {
		return ImportResult{}, err
	}
	owners, err := s.inventoryOwners(ctx, tenantID)
	if err != nil {
		return ImportResult{}, err
	}
	Allocate(recs, owners)

	res := ImportResult{Rows: len(recs), SHA256: digest, Allocation: map[string]float64{}}
	from, to := recs[0].UsageDate, recs[0].UsageDate
	for _, r := range recs {
		res.TotalUSD += r.CostUSD
		res.Allocation[r.Method] += r.CostUSD
		if r.UsageDate.Before(from) {
			from = r.UsageDate
		}
		if r.UsageDate.After(to) {
			to = r.UsageDate
		}
	}
	res.From, res.To = from.Format("2006-01-02"), to.Format("2006-01-02")
	if res.TotalUSD > 0 {
		res.Unallocated = round4(res.Allocation["unallocated"] / res.TotalUSD)
	}
	for k, v := range res.Allocation {
		res.Allocation[k] = round2(v)
	}
	res.TotalUSD = round2(res.TotalUSD)

	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO cost_imports (tenant_id, sha256, rows, from_date, to_date, total_usd, actor)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, tenantID, digest, len(recs), from, to, res.TotalUSD, actor).Scan(&res.ImportID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE cost_stage (LIKE cost_records INCLUDING DEFAULTS) ON COMMIT DROP`); err != nil {
			return err
		}
		rows := make([][]any, len(recs))
		for i, r := range recs {
			var cpu any
			if r.CPU != nil {
				cpu = float32(*r.CPU)
			}
			rows[i] = []any{tenantID, r.UsageDate, r.AccountID, r.Service, r.ResourceID, r.UsageType,
				r.CostUSD, r.Team, r.Environment, r.Method, cpu, res.ImportID}
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"cost_stage"},
			[]string{"tenant_id", "usage_date", "account_id", "service", "resource_id", "usage_type", "cost_usd", "team",
				"environment", "allocation_method", "cpu_utilization", "import_id"}, pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("stage cost rows: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cost_records SELECT * FROM cost_stage
			ON CONFLICT (tenant_id, usage_date, account_id, resource_id, usage_type) DO UPDATE SET
				service = EXCLUDED.service, cost_usd = EXCLUDED.cost_usd, team = EXCLUDED.team,
				environment = EXCLUDED.environment, allocation_method = EXCLUDED.allocation_method,
				cpu_utilization = EXCLUDED.cpu_utilization, import_id = EXCLUDED.import_id`); err != nil {
			return fmt.Errorf("upsert cost rows: %w", err)
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "cost.import", TargetType: "cost_import",
			TargetID: res.ImportID, Outcome: "success", Details: map[string]any{"rows": len(recs), "from": res.From, "to": res.To,
				"total_usd": res.TotalUSD, "sha256": digest}})
	})
	return res, err
}

func (s *Service) inventoryOwners(ctx context.Context, tenantID string) (map[string]Owner, error) {
	rows, err := s.Pool.Query(ctx, `SELECT resource_id, coalesce(tags->>'cost_center', ''), environment
		FROM resources WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Owner{}
	for rows.Next() {
		var id string
		var o Owner
		if err := rows.Scan(&id, &o.Team, &o.Environment); err != nil {
			return nil, err
		}
		out[id] = o
	}
	return out, rows.Err()
}

// ------------------------------------------------------------------ reports

// GroupBy columns allowed in summaries (whitelist; never interpolated from input).
var groupColumns = map[string]string{"team": "team", "service": "service", "environment": "environment",
	"account": "account_id", "allocation_method": "allocation_method"}

// Summary is a cost report for a period.
type Summary struct {
	From        string           `json:"from"`
	To          string           `json:"to"`
	GroupBy     string           `json:"group_by"`
	TotalUSD    float64          `json:"total_usd"`
	Groups      []Group          `json:"groups"`
	Unallocated float64          `json:"unallocated_share"`
	Monthly     []map[string]any `json:"monthly"`
}

// Group is one row of a summary.
type Group struct {
	Key   string  `json:"key"`
	USD   float64 `json:"usd"`
	Share float64 `json:"share"`
}

func parseRange(from, to string) (time.Time, time.Time, error) {
	f, err := time.Parse("2006-01-02", from)
	if from != "" && err != nil {
		return f, f, fmt.Errorf("%w: from must be YYYY-MM-DD", ErrInvalid)
	}
	t, err := time.Parse("2006-01-02", to)
	if to != "" && err != nil {
		return f, t, fmt.Errorf("%w: to must be YYYY-MM-DD", ErrInvalid)
	}
	if from == "" {
		f = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if to == "" {
		t = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if t.Before(f) {
		return f, t, fmt.Errorf("%w: to is before from", ErrInvalid)
	}
	return f, t, nil
}

// Summarize totals cost by a whitelisted dimension and by month.
func (s *Service) Summarize(ctx context.Context, tenant, groupBy, from, to string) (Summary, error) {
	col, ok := groupColumns[groupBy]
	if !ok {
		return Summary{}, fmt.Errorf("%w: group_by must be team, service, environment, account or allocation_method", ErrInvalid)
	}
	f, t, err := parseRange(from, to)
	if err != nil {
		return Summary{}, err
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return Summary{}, err
	}
	out := Summary{GroupBy: groupBy, Groups: []Group{}, Monthly: []map[string]any{}}
	var minD, maxD *time.Time
	if err := s.Pool.QueryRow(ctx, `SELECT coalesce(sum(cost_usd), 0)::float8, min(usage_date), max(usage_date),
		coalesce(sum(cost_usd) FILTER (WHERE team = ''), 0)::float8
		FROM cost_records WHERE tenant_id = $1 AND usage_date BETWEEN $2 AND $3`, tenantID, f, t).Scan(&out.TotalUSD, &minD, &maxD, &out.Unallocated); err != nil {
		return Summary{}, err
	}
	if minD == nil {
		return Summary{}, ErrNoData
	}
	out.From, out.To = minD.Format("2006-01-02"), maxD.Format("2006-01-02")
	if out.TotalUSD > 0 {
		out.Unallocated = round4(out.Unallocated / out.TotalUSD)
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+col+`, sum(cost_usd)::float8 FROM cost_records
		WHERE tenant_id = $1 AND usage_date BETWEEN $2 AND $3 GROUP BY 1 ORDER BY 2 DESC`, tenantID, f, t)
	if err != nil {
		return Summary{}, err
	}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.Key, &g.USD); err != nil {
			rows.Close()
			return Summary{}, err
		}
		if g.Key == "" {
			g.Key = "(unallocated)"
		}
		g.Share, g.USD = round4(g.USD/out.TotalUSD), round2(g.USD)
		out.Groups = append(out.Groups, g)
	}
	rows.Close()
	rows, err = s.Pool.Query(ctx, `SELECT to_char(date_trunc('month', usage_date), 'YYYY-MM'), sum(cost_usd)::float8,
		count(DISTINCT usage_date) FROM cost_records WHERE tenant_id = $1 AND usage_date BETWEEN $2 AND $3 GROUP BY 1 ORDER BY 1`, tenantID, f, t)
	if err != nil {
		return Summary{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var m string
		var usd float64
		var days int
		if err := rows.Scan(&m, &usd, &days); err != nil {
			return Summary{}, err
		}
		out.Monthly = append(out.Monthly, map[string]any{"month": m, "usd": round2(usd), "days": days})
	}
	out.TotalUSD = round2(out.TotalUSD)
	return out, rows.Err()
}

// TagCoverage reports how much spend is attributable to an owner.
func (s *Service) TagCoverage(ctx context.Context, tenant string) (map[string]any, error) {
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	rows, err := s.Pool.Query(ctx, `SELECT allocation_method, sum(cost_usd)::float8 FROM cost_records WHERE tenant_id = $1 GROUP BY 1`, tenantID)
	if err != nil {
		return nil, err
	}
	byMethod := map[string]float64{}
	total := 0.0
	for rows.Next() {
		var m string
		var v float64
		if err := rows.Scan(&m, &v); err != nil {
			rows.Close()
			return nil, err
		}
		byMethod[m], total = round2(v), total+v
	}
	rows.Close()
	if total == 0 {
		return nil, ErrNoData
	}
	out["by_method_usd"] = byMethod
	out["allocated_share"] = round4((total - byMethod["unallocated"]) / total)
	rows, err = s.Pool.Query(ctx, `SELECT CASE WHEN resource_id = '' THEN '(shared: '||service||')' ELSE resource_id END,
		sum(cost_usd)::float8 FROM cost_records WHERE tenant_id = $1 AND team = '' GROUP BY 1 ORDER BY 2 DESC LIMIT 20`, tenantID)
	if err != nil {
		return nil, err
	}
	var top []map[string]any
	for rows.Next() {
		var id string
		var v float64
		if err := rows.Scan(&id, &v); err != nil {
			rows.Close()
			return nil, err
		}
		top = append(top, map[string]any{"resource": id, "usd": round2(v)})
	}
	rows.Close()
	out["top_unallocated"] = top
	return out, nil
}

// --------------------------------------------------------- recommendations

// RecView is a stored recommendation with measured savings when implemented.
type RecView struct {
	ID               string         `json:"id"`
	Kind             string         `json:"kind"`
	ResourceID       string         `json:"resource_id"`
	Team             string         `json:"team"`
	AsOf             string         `json:"as_of"`
	Details          map[string]any `json:"details"`
	ProjectedMonthly float64        `json:"projected_monthly_savings"`
	Status           string         `json:"status"`
	DecidedBy        string         `json:"decided_by,omitempty"`
	ImplementedAt    string         `json:"implemented_at,omitempty"`
	MeasuredMonthly  *float64       `json:"measured_monthly_savings,omitempty"`
	MeasurementNote  string         `json:"measurement_note,omitempty"`
}

// GenerateRecommendations evaluates the rules over the WindowDays ending at
// asOf (default: the latest cost date) and upserts open recommendations.
func (s *Service) GenerateRecommendations(ctx context.Context, tenant, actor, asOf string) ([]RecView, error) {
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return nil, err
	}
	var end time.Time
	if asOf == "" {
		var last *time.Time
		if err := s.Pool.QueryRow(ctx, `SELECT max(usage_date) FROM cost_records WHERE tenant_id = $1`, tenantID).Scan(&last); err != nil {
			return nil, err
		}
		if last == nil {
			return nil, ErrNoData
		}
		end = *last
	} else if end, err = time.Parse("2006-01-02", asOf); err != nil {
		return nil, fmt.Errorf("%w: as_of must be YYYY-MM-DD", ErrInvalid)
	}
	start := end.AddDate(0, 0, -(WindowDays - 1))
	rows, err := s.Pool.Query(ctx, `SELECT resource_id, service, usage_type, team, environment, usage_date, cost_usd::float8, cpu_utilization
		FROM cost_records WHERE tenant_id = $1 AND usage_date BETWEEN $2 AND $3 AND resource_id <> ''
		ORDER BY resource_id, usage_date`, tenantID, start, end)
	if err != nil {
		return nil, err
	}
	byRes := map[string]*ResourceUsage{}
	var order []string
	for rows.Next() {
		var id, svc, ut, team, env string
		var d time.Time
		var c float64
		var cpu *float32
		if err := rows.Scan(&id, &svc, &ut, &team, &env, &d, &c, &cpu); err != nil {
			rows.Close()
			return nil, err
		}
		u := byRes[id]
		if u == nil {
			u = &ResourceUsage{ResourceID: id, Service: svc, Team: team, Environment: env}
			byRes[id] = u
			order = append(order, id)
		}
		u.UsageType = ut // latest size wins
		day := Day{Date: d, Cost: c}
		if cpu != nil {
			v := float64(*cpu)
			day.CPU = &v
		}
		u.Days = append(u.Days, day)
	}
	rows.Close()
	usages := make([]ResourceUsage, 0, len(order))
	for _, id := range order {
		usages = append(usages, *byRes[id])
	}
	recs := Recommend(usages)

	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		for _, r := range recs {
			if _, err := tx.Exec(ctx, `INSERT INTO recommendations (tenant_id, kind, resource_id, team, as_of, details, projected_monthly_savings)
				VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (tenant_id, kind, resource_id) WHERE status = 'open' DO UPDATE SET
					as_of = EXCLUDED.as_of, details = EXCLUDED.details, projected_monthly_savings = EXCLUDED.projected_monthly_savings`,
				tenantID, r.Kind, r.ResourceID, r.Team, end, mustJSON(r.Details), r.ProjectedMonthly); err != nil {
				return err
			}
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "recommendations.generate", TargetType: "tenant",
			TargetID: tenantID, Outcome: "success", Details: map[string]any{"as_of": end.Format("2006-01-02"), "count": len(recs)}})
	})
	if err != nil {
		return nil, err
	}
	return s.ListRecommendations(ctx, tenant, "open")
}

// ListRecommendations lists recommendations (optionally by status), largest projected saving first.
func (s *Service) ListRecommendations(ctx context.Context, tenant, status string) ([]RecView, error) {
	if status != "" && status != "open" && status != "accepted" && status != "dismissed" && status != "implemented" {
		return nil, fmt.Errorf("%w: unknown status", ErrInvalid)
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT id, kind, resource_id, team, as_of::text, details, projected_monthly_savings::float8,
		status, coalesce(decided_by, ''), coalesce(implemented_at::text, '')
		FROM recommendations WHERE tenant_id = $1 AND ($2 = '' OR status = $2)
		ORDER BY projected_monthly_savings DESC, resource_id LIMIT 500`, tenantID, status)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (RecView, error) {
		var v RecView
		var d []byte
		err := row.Scan(&v.ID, &v.Kind, &v.ResourceID, &v.Team, &v.AsOf, &d, &v.ProjectedMonthly, &v.Status, &v.DecidedBy, &v.ImplementedAt)
		if err == nil {
			err = json.Unmarshal(d, &v.Details)
		}
		return v, err
	})
	if err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Status == "implemented" {
			s.measure(ctx, tenantID, &out[i])
		}
	}
	if out == nil {
		out = []RecView{}
	}
	return out, nil
}

// measure compares the resource's average daily cost in the 14 days before
// and after implementation. It is labelled as measured on imported data; on
// synthetic data it is a simulation, not a real saving.
func (s *Service) measure(ctx context.Context, tenantID string, v *RecView) {
	impl, err := time.Parse("2006-01-02", v.ImplementedAt)
	if err != nil {
		return
	}
	var before, after *float64
	var nAfter int
	_ = s.Pool.QueryRow(ctx, `SELECT
			avg(cost_usd) FILTER (WHERE usage_date >= $3::date - 14 AND usage_date < $3)::float8,
			avg(cost_usd) FILTER (WHERE usage_date >= $3 AND usage_date < $3::date + 14)::float8,
			count(*) FILTER (WHERE usage_date >= $3 AND usage_date < $3::date + 14)
		FROM cost_records WHERE tenant_id = $1 AND resource_id = $2`, tenantID, v.ResourceID, impl).Scan(&before, &after, &nAfter)
	if before == nil || after == nil || nAfter < 7 {
		v.MeasurementNote = "not enough cost data after implementation (need 7+ days)"
		return
	}
	m := round2((*before - *after) * daysPerMonth)
	v.MeasuredMonthly = &m
	v.MeasurementNote = "measured from imported cost data: 14-day average before vs after implementation (synthetic data = simulated, not real savings)"
}

var transitions = map[string][2]string{
	"accept":    {"open", "accepted"},
	"dismiss":   {"open", "dismissed"},
	"implement": {"accepted", "implemented"},
}

// DecideRecommendation moves a recommendation through its lifecycle.
func (s *Service) DecideRecommendation(ctx context.Context, tenant, actor, id, action, implementedAt string) (RecView, error) {
	if !uuidRe.MatchString(id) {
		return RecView{}, ErrNotFound
	}
	tr, ok := transitions[action]
	if !ok {
		return RecView{}, fmt.Errorf("%w: unknown action", ErrInvalid)
	}
	var impl any
	if action == "implement" {
		d, err := time.Parse("2006-01-02", implementedAt)
		if err != nil {
			return RecView{}, fmt.Errorf("%w: implemented_at must be YYYY-MM-DD", ErrInvalid)
		}
		impl = d
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return RecView{}, err
	}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE recommendations SET status = $4, decided_by = $5, implemented_at = coalesce($6, implemented_at)
			WHERE tenant_id = $1 AND id = $2 AND status = $3`, tenantID, id, tr[0], tr[1], actor, impl)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			_ = tx.QueryRow(ctx, `SELECT true FROM recommendations WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(&exists)
			if !exists {
				return ErrNotFound
			}
			return ErrConflict
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "recommendation." + action, TargetType: "recommendation",
			TargetID: id, Outcome: "success", Details: map[string]any{"from": tr[0], "to": tr[1]}})
	})
	if err != nil {
		return RecView{}, err
	}
	all, err := s.ListRecommendations(ctx, tenant, tr[1])
	if err != nil {
		return RecView{}, err
	}
	for _, v := range all {
		if v.ID == id {
			return v, nil
		}
	}
	return RecView{}, ErrNotFound
}

// ---------------------------------------------------------------- ML results

// MLResult is the latest model output of one kind for the tenant.
type MLResult struct {
	RunID     string           `json:"run_id"`
	Model     string           `json:"model"`
	Params    map[string]any   `json:"params"`
	Versions  map[string]any   `json:"versions"`
	DataFrom  string           `json:"data_from"`
	DataTo    string           `json:"data_to"`
	CreatedAt time.Time        `json:"created_at"`
	Points    []map[string]any `json:"points"`
}

// LatestML returns the newest anomaly or forecast run, optionally filtered by entity.
func (s *Service) LatestML(ctx context.Context, tenant, kind, entity string) (MLResult, error) {
	if kind != "anomaly" && kind != "forecast" {
		return MLResult{}, fmt.Errorf("%w: kind", ErrInvalid)
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return MLResult{}, err
	}
	var r MLResult
	var params, versions []byte
	err = s.Pool.QueryRow(ctx, `SELECT id, model, params, versions, data_from::text, data_to::text, created_at FROM ml_runs
		WHERE tenant_id = $1 AND kind = $2 ORDER BY created_at DESC LIMIT 1`, tenantID, kind).Scan(
		&r.RunID, &r.Model, &params, &versions, &r.DataFrom, &r.DataTo, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return MLResult{}, ErrNoData
	}
	if err != nil {
		return MLResult{}, err
	}
	_ = json.Unmarshal(params, &r.Params)
	_ = json.Unmarshal(versions, &r.Versions)
	q := `SELECT entity, usage_date::text, predicted::float8, NULL::float8, NULL::float8 FROM cost_forecasts WHERE run_id = $1 AND ($2 = '' OR entity = $2) ORDER BY entity, usage_date`
	if kind == "anomaly" {
		q = `SELECT entity, usage_date::text, observed::float8, expected::float8, score::float8 FROM cost_anomalies WHERE run_id = $1 AND ($2 = '' OR entity = $2) ORDER BY usage_date DESC, entity`
	}
	rows, err := s.Pool.Query(ctx, q, r.RunID, entity)
	if err != nil {
		return MLResult{}, err
	}
	defer rows.Close()
	r.Points = []map[string]any{}
	for rows.Next() {
		var e, d string
		var v float64
		var exp, score *float64
		if err := rows.Scan(&e, &d, &v, &exp, &score); err != nil {
			return MLResult{}, err
		}
		p := map[string]any{"entity": e, "date": d}
		if kind == "forecast" {
			p["predicted_usd"] = round2(v)
		} else {
			p["observed_usd"], p["expected_usd"], p["score"] = round2(v), round2(*exp), round2(*score)
		}
		r.Points = append(r.Points, p)
	}
	return r, rows.Err()
}

func round4(v float64) float64 { return float64(int64(v*10000+0.5)) / 10000 }

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
