package risk

import (
	"context"
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
	ErrNoEvaluation   = errors.New("no inventory compliance evaluation yet; run POST /api/v1/compliance/evaluations first")
	ErrInvalid        = errors.New("invalid request")
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RuleInfo is the catalog metadata the risk engine needs.
type RuleInfo struct {
	Severity string
	Controls int
}

// Service is the risk module.
type Service struct {
	Pool  *pgxpool.Pool
	Rules map[string]RuleInfo
	Now   func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Summary is stored with each run.
type Summary struct {
	Findings     int                 `json:"findings"`
	Excepted     int                 `json:"excepted_not_scored"`
	ByBand       map[string]int      `json:"by_band"`
	VsSeverity   Comparison          `json:"vs_severity"`
	Sensitivity  []SensitivityResult `json:"sensitivity"`
	AttackPaths  int                 `json:"internet_reachable_sensitive_targets"`
	GraphNodes   int                 `json:"graph_nodes"`
	GraphEdges   int                 `json:"graph_edges"`
	ModelVersion string              `json:"model_version"`
}

// Run is a stored assessment run.
type Run struct {
	ID              string       `json:"id"`
	ComplianceRunID string       `json:"compliance_run_id"`
	Weights         Weights      `json:"weights"`
	Actor           string       `json:"actor"`
	Summary         Summary      `json:"summary"`
	CreatedAt       time.Time    `json:"created_at"`
	Assessments     []Assessment `json:"assessments"`
}

func (s *Service) tenantID(ctx context.Context, slug string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, slug).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTenantNotFound
	}
	return id, err
}

// LoadGraph builds the graph from the tenant's live inventory.
func (s *Service) LoadGraph(ctx context.Context, tenantID string) (*Graph, int, error) {
	rows, err := s.Pool.Query(ctx, `SELECT resource_id, resource_type, environment, tags, configuration
		FROM resources WHERE tenant_id = $1 AND deleted_at IS NULL`, tenantID)
	if err != nil {
		return nil, 0, err
	}
	var nodes []Node
	for rows.Next() {
		var id, typ, env string
		var tags, cfg []byte
		if err := rows.Scan(&id, &typ, &env, &tags, &cfg); err != nil {
			rows.Close()
			return nil, 0, err
		}
		n, err := NodeFromJSON(id, typ, env, tags, cfg)
		if err != nil {
			rows.Close()
			return nil, 0, err
		}
		nodes = append(nodes, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT source_resource_id, relationship_type, target_resource_id
		FROM resource_relationships WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, 0, err
	}
	edges, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Edge])
	if err != nil {
		return nil, 0, err
	}
	return BuildGraph(nodes, edges), len(edges), nil
}

// Assess scores the failing findings of the latest inventory compliance run.
func (s *Service) Assess(ctx context.Context, tenant, actor string, w Weights) (Run, error) {
	if err := w.Validate(); err != nil {
		return Run{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return Run{}, err
	}
	var compRun string
	err = s.Pool.QueryRow(ctx, `SELECT id FROM compliance_runs WHERE tenant_id = $1 AND source = 'inventory'
		ORDER BY evaluated_at DESC LIMIT 1`, tenantID).Scan(&compRun)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNoEvaluation
	}
	if err != nil {
		return Run{}, err
	}

	// Failing findings with the start of their current continuous failure.
	rows, err := s.Pool.Query(ctx, `
		WITH fails AS (
			SELECT rule_id, subject FROM compliance_evaluations WHERE run_id = $2 AND result = 'fail'
		), hist AS (
			SELECT e.rule_id, e.subject, e.result, r.evaluated_at
			FROM compliance_evaluations e JOIN compliance_runs r ON r.id = e.run_id
			JOIN fails f ON f.rule_id = e.rule_id AND f.subject = e.subject
			WHERE e.tenant_id = $1 AND r.tenant_id = $1 AND r.source = 'inventory'
		), last_ok AS (
			SELECT rule_id, subject, max(evaluated_at) AS at FROM hist WHERE result <> 'fail' GROUP BY rule_id, subject
		)
		SELECT f.rule_id, f.subject, min(h.evaluated_at)
		FROM fails f
		JOIN hist h ON h.rule_id = f.rule_id AND h.subject = f.subject AND h.result = 'fail'
		LEFT JOIN last_ok o ON o.rule_id = f.rule_id AND o.subject = f.subject
		WHERE h.evaluated_at > coalesce(o.at, '-infinity')
		GROUP BY f.rule_id, f.subject`, tenantID, compRun)
	if err != nil {
		return Run{}, err
	}
	var findings []Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.RuleID, &f.Subject, &f.FirstSeen); err != nil {
			rows.Close()
			return Run{}, err
		}
		info := s.Rules[f.RuleID]
		f.Severity, f.Controls = info.Severity, info.Controls
		if f.Severity == "" {
			f.Severity = "medium"
		}
		findings = append(findings, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Run{}, err
	}
	var excepted int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM compliance_evaluations WHERE run_id = $1 AND result = 'excepted'`, compRun).Scan(&excepted); err != nil {
		return Run{}, fmt.Errorf("excepted count: %w", err)
	}

	g, nEdges, err := s.LoadGraph(ctx, tenantID)
	if err != nil {
		return Run{}, err
	}
	now := s.now()
	as := Assess(g, findings, w, now)

	sum := Summary{Findings: len(as), Excepted: excepted, ByBand: map[string]int{}, ModelVersion: ModelVersion,
		VsSeverity: CompareWithSeverity(as, 20), AttackPaths: len(g.AttackPaths(50, 0)), GraphNodes: len(g.Nodes), GraphEdges: nEdges}
	ranked := make([]Ranked, len(as))
	for i, a := range as {
		sum.ByBand[a.Band]++
		ranked[i] = Ranked{Key: a.RuleID + "|" + a.Subject, Factors: a.Factors}
	}
	if len(ranked) >= 2 {
		sum.Sensitivity, _ = SensitivityAnalysis(ranked, w, 0.2, 20)
	}

	run := Run{ComplianceRunID: compRun, Weights: w, Actor: actor, Summary: sum, Assessments: as}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO risk_runs (tenant_id, compliance_run_id, model_version, weights, actor, summary)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
			tenantID, compRun, ModelVersion, mustJSON(w), actor, mustJSON(sum)).Scan(&run.ID, &run.CreatedAt); err != nil {
			return err
		}
		rows := make([][]any, 0, len(as))
		for _, a := range as {
			path := a.AttackPath
			if path == nil {
				path = []Hop{}
			}
			rows = append(rows, []any{run.ID, a.RuleID, a.Subject, a.ResourceType, a.RuleSeverity, a.Score, a.Band,
				mustJSON(a.Factors), mustJSON(a.Contributions), mustJSON(a.Reasons), a.BlastRadius, mustJSON(path), a.FirstSeen})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"risk_assessments"},
			[]string{"run_id", "rule_id", "subject", "resource_type", "rule_severity", "score", "band", "factors",
				"contributions", "reasons", "blast_radius", "attack_path", "first_seen"}, pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("store assessments: %w", err)
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "risk.assess", TargetType: "risk_run",
			TargetID: run.ID, Outcome: "success", Details: map[string]any{"compliance_run_id": compRun, "findings": len(as),
				"by_band": sum.ByBand, "model_version": ModelVersion}})
	})
	return run, err
}

var bandRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

// GetRun returns a stored run, assessments ordered by score.
// id may be "latest" for the tenant's most recent run.
func (s *Service) GetRun(ctx context.Context, tenant, id, minBand string, limit int) (Run, error) {
	if id != "latest" && !uuidRe.MatchString(id) {
		return Run{}, ErrNotFound
	}
	maxRank := 3
	if minBand != "" {
		r, ok := bandRank[minBand]
		if !ok {
			return Run{}, fmt.Errorf("%w: unknown band %q", ErrInvalid, minBand)
		}
		maxRank = r
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return Run{}, err
	}
	var r Run
	var weights, summary []byte
	err = s.Pool.QueryRow(ctx, `SELECT id, compliance_run_id, weights, actor, summary, created_at FROM risk_runs
		WHERE tenant_id = $1 AND ($2 = 'latest' OR id::text = $2) ORDER BY created_at DESC, id LIMIT 1`, tenantID, id).Scan(&r.ID, &r.ComplianceRunID, &weights, &r.Actor, &summary, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil {
		return Run{}, err
	}
	_ = json.Unmarshal(weights, &r.Weights)
	_ = json.Unmarshal(summary, &r.Summary)
	var bands []string
	for b, rank := range bandRank {
		if rank <= maxRank {
			bands = append(bands, b)
		}
	}
	rows, err := s.Pool.Query(ctx, `SELECT rule_id, subject, resource_type, rule_severity, score::float8, band, factors,
		contributions, reasons, blast_radius, attack_path, first_seen
		FROM risk_assessments WHERE run_id = $1 AND band = ANY($2)
		ORDER BY score DESC, subject, rule_id LIMIT $3`, r.ID, bands, limit)
	if err != nil {
		return Run{}, err
	}
	r.Assessments, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Assessment, error) {
		var a Assessment
		var f, c, rs, p []byte
		if err := row.Scan(&a.RuleID, &a.Subject, &a.ResourceType, &a.RuleSeverity, &a.Score, &a.Band, &f, &c, &rs,
			&a.BlastRadius, &p, &a.FirstSeen); err != nil {
			return a, err
		}
		for _, x := range []struct {
			b []byte
			v any
		}{{f, &a.Factors}, {c, &a.Contributions}, {rs, &a.Reasons}, {p, &a.AttackPath}} {
			if err := json.Unmarshal(x.b, x.v); err != nil {
				return a, err
			}
		}
		a.Controls = s.Rules[a.RuleID].Controls
		return a, nil
	})
	if r.Assessments == nil {
		r.Assessments = []Assessment{}
	}
	return r, err
}

// AttackPaths computes current attack paths for the tenant.
func (s *Service) AttackPaths(ctx context.Context, tenant string, minSensitivity, limit int) ([]Path, error) {
	if minSensitivity < 0 || minSensitivity > 100 {
		return nil, fmt.Errorf("%w: min_sensitivity must be 0-100", ErrInvalid)
	}
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return nil, err
	}
	g, _, err := s.LoadGraph(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	paths := g.AttackPaths(minSensitivity, limit)
	if paths == nil {
		paths = []Path{}
	}
	return paths, nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
