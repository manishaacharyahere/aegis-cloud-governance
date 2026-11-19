package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/paging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/tenancy"
)

// Errors returned by the service.
var (
	ErrTenantNotFound = errors.New("tenant not found")
	ErrNotFound       = errors.New("not found")
	ErrInvalid        = errors.New("invalid request")
	ErrSelfApproval   = errors.New("an exception cannot be decided by the person who requested it")
	ErrConflict       = errors.New("exception is not in a state that allows this transition")
	ErrScanNotReady   = errors.New("scan has not succeeded or has no recorded policy bundle")
)

// MaxExceptionLifetime bounds how long any exception may last.
const MaxExceptionLifetime = 365 * 24 * time.Hour

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Service is the compliance module.
type Service struct {
	Pool    *pgxpool.Pool
	Catalog *Catalog
	OPA     opa.Querier
	Now     func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) tenantID(ctx context.Context, slug string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, slug).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTenantNotFound
	}
	return id, err
}

// RunSummary describes one evaluation run.
type RunSummary struct {
	RunID              string    `json:"run_id"`
	Source             string    `json:"source"`
	SourceKey          string    `json:"source_key"`
	SourceRef          string    `json:"source_ref"`
	PolicyBundleSHA256 string    `json:"policy_bundle_sha256"`
	CatalogSHA256      string    `json:"catalog_sha256"`
	EvaluatedAt        time.Time `json:"evaluated_at"`
	Pass               int       `json:"pass"`
	Fail               int       `json:"fail"`
	Excepted           int       `json:"excepted"`
}

// EvaluateInventory evaluates every live inventory resource of the tenant
// with the aegis.inventory policies.
func (s *Service) EvaluateInventory(ctx context.Context, tenant, actor string) (RunSummary, error) {
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return RunSummary{}, err
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, account_id, resource_id, resource_type, region, tags, configuration, current_version, content_sha256
		FROM resources WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY resource_id`, tenantID)
	if err != nil {
		return RunSummary{}, err
	}
	var docs []opa.Resource
	var subjects []Subject
	accounts := map[string]bool{}
	for rows.Next() {
		var pk, account, sha string
		var version int
		var d opa.Resource
		var tags, cfg []byte
		if err := rows.Scan(&pk, &account, &d.ID, &d.Type, &d.Region, &tags, &cfg, &version, &sha); err != nil {
			rows.Close()
			return RunSummary{}, err
		}
		_ = json.Unmarshal(tags, &d.Tags)
		_ = json.Unmarshal(cfg, &d.Configuration)
		docs = append(docs, d)
		accounts[account] = true
		subjects = append(subjects, Subject{Kind: KindInventory, Label: d.ID, Type: d.Type, Taggable: true, Region: d.Region,
			Exists: true, Evidence: map[string]any{"resource_pk": pk, "version": version, "content_sha256": sha, "account_id": account}})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return RunSummary{}, err
	}
	if len(docs) == 0 {
		return RunSummary{}, fmt.Errorf("%w: tenant has no inventory to evaluate", ErrInvalid)
	}

	bundle, err := s.OPA.Bundle(ctx)
	if err != nil {
		return RunSummary{}, fmt.Errorf("policy bundle: %w", err)
	}
	pcfg, err := tenancy.Load(ctx, s.Pool, tenantID)
	if err != nil {
		return RunSummary{}, err
	}
	results, err := opa.EvaluateInventory(ctx, s.OPA, docs, pcfg.Input())
	if err != nil {
		return RunSummary{}, err
	}
	findings := make([]PolicyFinding, 0, len(results))
	for _, f := range results {
		findings = append(findings, PolicyFinding{RuleID: f.RuleID, Subject: f.Address, Message: f.Message})
	}
	ref := make([]string, 0, len(accounts))
	for a := range accounts {
		ref = append(ref, a)
	}
	sort.Strings(ref)
	return s.saveRun(ctx, tenantID, "inventory", "inventory", strings.Join(ref, ","), bundle.SHA256, bundle.Modules, actor, subjects, findings)
}

// EvaluateScan turns a succeeded IaC scan into compliance evidence. It
// reuses the decisions recorded by the scan (and the policy bundle that
// produced them) rather than re-evaluating, so the evidence matches exactly
// what was reported at scan time.
func (s *Service) EvaluateScan(ctx context.Context, tenant, scanID, actor string) (RunSummary, error) {
	if !uuidRe.MatchString(scanID) {
		return RunSummary{}, ErrNotFound
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return RunSummary{}, err
	}
	var status, fixture string
	var bundleSHA *string
	err = s.Pool.QueryRow(ctx, `SELECT s.status, s.source_ref, b.sha256 FROM iac_scans s
		LEFT JOIN policy_bundles b ON b.sha256 = s.policy_bundle_sha256
		WHERE s.tenant_id = $1 AND s.id = $2`, tenantID, scanID).Scan(&status, &fixture, &bundleSHA)
	if errors.Is(err, pgx.ErrNoRows) {
		return RunSummary{}, ErrNotFound
	}
	if err != nil {
		return RunSummary{}, err
	}
	if status != "succeeded" || bundleSHA == nil {
		return RunSummary{}, ErrScanNotReady
	}

	rows, err := s.Pool.Query(ctx, `SELECT address, resource_type, action, region, detail FROM iac_planned_changes WHERE scan_id = $1`, scanID)
	if err != nil {
		return RunSummary{}, err
	}
	var subjects []Subject
	for rows.Next() {
		var addr, typ, action, region string
		var detail []byte
		if err := rows.Scan(&addr, &typ, &action, &region, &detail); err != nil {
			rows.Close()
			return RunSummary{}, err
		}
		var d struct {
			Taggable bool `json:"taggable"`
		}
		_ = json.Unmarshal(detail, &d)
		subjects = append(subjects, Subject{Kind: KindPlanned, Label: addr, Type: typ, Taggable: d.Taggable, Region: region,
			Exists: action != "delete", Evidence: map[string]any{"scan_id": scanID, "address": addr, "action": action}})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return RunSummary{}, err
	}

	rows, err = s.Pool.Query(ctx, `SELECT rule_id, resource_address, title FROM iac_findings WHERE scan_id = $1 AND source = 'aegis-policy'`, scanID)
	if err != nil {
		return RunSummary{}, err
	}
	findings, err := pgx.CollectRows(rows, pgx.RowToStructByPos[PolicyFinding])
	if err != nil {
		return RunSummary{}, err
	}
	return s.saveRun(ctx, tenantID, "iac_scan", fixture, scanID, *bundleSHA, nil, actor, subjects, findings)
}

func (s *Service) saveRun(ctx context.Context, tenantID, source, key, ref, bundleSHA string, modules map[string]string,
	actor string, subjects []Subject, findings []PolicyFinding) (RunSummary, error) {
	var sum RunSummary
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if err := recordCatalog(ctx, tx, s.Catalog); err != nil {
			return err
		}
		if modules != nil {
			if _, err := tx.Exec(ctx, `INSERT INTO policy_bundles (sha256, modules) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
				bundleSHA, mustJSON(modules)); err != nil {
				return fmt.Errorf("record policy bundle: %w", err)
			}
		}
		exs, err := activeExceptions(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		evs := Evaluate(s.Catalog, subjects, findings, exs, now)
		pass, fail, exc := Tally(evs)

		var runID string
		if err := tx.QueryRow(ctx, `
			INSERT INTO compliance_runs (tenant_id, source, source_key, source_ref, policy_bundle_sha256, catalog_sha256,
				actor, evaluated_at, pass_count, fail_count, excepted_count)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
			tenantID, source, key, ref, bundleSHA, s.Catalog.SHA256, actor, now, pass, fail, exc).Scan(&runID); err != nil {
			return fmt.Errorf("insert run: %w", err)
		}
		rows := make([][]any, 0, len(evs))
		for _, e := range evs {
			var exID any
			if e.ExceptionID != "" {
				exID = e.ExceptionID
			}
			rows = append(rows, []any{runID, tenantID, e.RuleID, e.SubjectKind, e.Subject, e.Result, exID, e.Message, mustJSON(e.Evidence)})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"compliance_evaluations"},
			[]string{"run_id", "tenant_id", "rule_id", "subject_kind", "subject", "result", "exception_id", "message", "evidence"},
			pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("insert evaluations: %w", err)
		}
		if err := audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "compliance.evaluate", TargetType: "compliance_run",
			TargetID: runID, Outcome: "success", Details: map[string]any{"source": source, "source_ref": ref,
				"pass": pass, "fail": fail, "excepted": exc, "policy_bundle_sha256": bundleSHA, "catalog_sha256": s.Catalog.SHA256}}); err != nil {
			return err
		}
		sum = RunSummary{RunID: runID, Source: source, SourceKey: key, SourceRef: ref, PolicyBundleSHA256: bundleSHA,
			CatalogSHA256: s.Catalog.SHA256, EvaluatedAt: now, Pass: pass, Fail: fail, Excepted: exc}
		return nil
	})
	// A large run changes the table enough that the planner's statistics go
	// stale; refresh them now (risk assessment queries this table next).
	if err == nil && sum.Pass+sum.Fail+sum.Excepted >= 1000 {
		if _, aerr := s.Pool.Exec(ctx, `SELECT aegis_analyze('compliance_evaluations')`); aerr != nil {
			logging.FromContext(ctx).Warn("analyze after compliance run failed", "error", aerr)
		}
	}
	return sum, err
}

func recordCatalog(ctx context.Context, tx pgx.Tx, c *Catalog) error {
	_, err := tx.Exec(ctx, `INSERT INTO catalog_versions (sha256, version, content) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		c.SHA256, c.Version, catalogJSON)
	if err != nil {
		return fmt.Errorf("record catalog: %w", err)
	}
	return nil
}

func activeExceptions(ctx context.Context, q pgx.Tx, tenantID string) ([]Exception, error) {
	rows, err := q.Query(ctx, `SELECT id, rule_id, subject, status, expires_at FROM policy_exceptions
		WHERE tenant_id = $1 AND status = 'approved' AND expires_at > now()`, tenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Exception])
}

// ---------------------------------------------------------------- coverage

// Scopes select which evidence counts toward coverage.
const (
	ScopeObserved = "observed" // latest inventory evaluation
	ScopePlanned  = "planned"  // latest evaluation of each scanned fixture
	ScopeAll      = "all"
)

// RuleStatus is one mapped rule's contribution to a control.
type RuleStatus struct {
	RuleID       string `json:"rule_id"`
	Title        string `json:"title"`
	Severity     string `json:"severity"`
	Coverage     string `json:"coverage"`
	ReviewStatus string `json:"review_status"`
	Pass         int    `json:"pass"`
	Fail         int    `json:"fail"`
	Excepted     int    `json:"excepted"`
}

// ControlStatus is the compliance state of one control.
type ControlStatus struct {
	Framework       string       `json:"framework"`
	ControlID       string       `json:"control_id"`
	Title           string       `json:"title"`
	Status          string       `json:"status"` // failing | passing | no_evidence | not_covered
	Stale           bool         `json:"stale"`
	LastEvaluatedAt *time.Time   `json:"last_evaluated_at,omitempty"`
	Pass            int          `json:"pass"`
	Fail            int          `json:"fail"`
	Excepted        int          `json:"excepted"`
	Rules           []RuleStatus `json:"rules"`
}

// Coverage is a framework-level report.
type Coverage struct {
	Framework     Framework       `json:"framework"`
	Scope         string          `json:"scope"`
	StaleAfter    string          `json:"stale_after"`
	CatalogSHA256 string          `json:"catalog_sha256"`
	Notice        string          `json:"notice"`
	Runs          []RunSummary    `json:"runs"`
	Summary       map[string]int  `json:"summary"`
	Controls      []ControlStatus `json:"controls"`
}

type ruleAgg struct {
	pass, fail, excepted int
	last                 *time.Time
}

func (s *Service) latestRuns(ctx context.Context, tenantID, scope string) ([]RunSummary, error) {
	cond := ""
	switch scope {
	case ScopeObserved:
		cond = "AND source = 'inventory'"
	case ScopePlanned:
		cond = "AND source = 'iac_scan'"
	case ScopeAll:
	default:
		return nil, fmt.Errorf("%w: scope must be observed, planned or all", ErrInvalid)
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT DISTINCT ON (source, source_key) id, source, source_key, source_ref, policy_bundle_sha256, catalog_sha256,
		       evaluated_at, pass_count, fail_count, excepted_count
		FROM compliance_runs WHERE tenant_id = $1 `+cond+`
		ORDER BY source, source_key, evaluated_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[RunSummary])
}

func (s *Service) aggregate(ctx context.Context, runs []RunSummary) (map[string]*ruleAgg, error) {
	ids := make([]string, len(runs))
	for i, r := range runs {
		ids[i] = r.RunID
	}
	out := map[string]*ruleAgg{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT e.rule_id, e.result, count(*), max(r.evaluated_at)
		FROM compliance_evaluations e JOIN compliance_runs r ON r.id = e.run_id
		WHERE e.run_id = ANY($1::uuid[]) GROUP BY e.rule_id, e.result`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var rule, result string
		var n int
		var last time.Time
		if err := rows.Scan(&rule, &result, &n, &last); err != nil {
			return nil, err
		}
		a := out[rule]
		if a == nil {
			a = &ruleAgg{}
			out[rule] = a
		}
		switch result {
		case ResultPass:
			a.pass += n
		case ResultFail:
			a.fail += n
		case ResultExcepted:
			a.excepted += n
		}
		if a.last == nil || last.After(*a.last) {
			l := last
			a.last = &l
		}
	}
	return out, rows.Err()
}

func (s *Service) controlStatus(f Framework, ctl Control, agg map[string]*ruleAgg, staleAfter time.Duration, now time.Time) ControlStatus {
	cs := ControlStatus{Framework: f.ID, ControlID: ctl.ID, Title: ctl.Title, Rules: []RuleStatus{}}
	maps := s.Catalog.MappingsFor(f.ID, ctl.ID)
	if len(maps) == 0 {
		cs.Status = "not_covered"
		return cs
	}
	for _, m := range maps {
		r, _ := s.Catalog.Rule(m.Rule)
		rs := RuleStatus{RuleID: r.ID, Title: r.Title, Severity: r.Severity, Coverage: m.Coverage, ReviewStatus: m.ReviewStatus}
		if a := agg[r.ID]; a != nil {
			rs.Pass, rs.Fail, rs.Excepted = a.pass, a.fail, a.excepted
			if a.last != nil && (cs.LastEvaluatedAt == nil || a.last.After(*cs.LastEvaluatedAt)) {
				cs.LastEvaluatedAt = a.last
			}
		}
		cs.Pass, cs.Fail, cs.Excepted = cs.Pass+rs.Pass, cs.Fail+rs.Fail, cs.Excepted+rs.Excepted
		cs.Rules = append(cs.Rules, rs)
	}
	switch {
	case cs.Fail > 0:
		cs.Status = "failing"
	case cs.Pass+cs.Excepted > 0:
		cs.Status = "passing"
	default:
		cs.Status = "no_evidence"
	}
	cs.Stale = cs.LastEvaluatedAt != nil && now.Sub(*cs.LastEvaluatedAt) > staleAfter
	return cs
}

// Coverage reports every catalog control of a framework.
func (s *Service) Coverage(ctx context.Context, tenant, framework, scope string, staleAfter time.Duration) (Coverage, error) {
	f, ok := s.Catalog.Framework(framework)
	if !ok {
		return Coverage{}, ErrNotFound
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return Coverage{}, err
	}
	runs, err := s.latestRuns(ctx, tenantID, scope)
	if err != nil {
		return Coverage{}, err
	}
	agg, err := s.aggregate(ctx, runs)
	if err != nil {
		return Coverage{}, err
	}
	cov := Coverage{Framework: f, Scope: scope, StaleAfter: staleAfter.String(), CatalogSHA256: s.Catalog.SHA256,
		Notice: s.Catalog.Notice, Runs: runs, Summary: map[string]int{"total": len(f.Controls)}}
	if cov.Runs == nil {
		cov.Runs = []RunSummary{}
	}
	cov.Framework.Controls = nil
	now := s.now()
	for _, ctl := range f.Controls {
		cs := s.controlStatus(f, ctl, agg, staleAfter, now)
		cov.Summary[cs.Status]++
		if cs.Stale {
			cov.Summary["stale"]++
		}
		cov.Controls = append(cov.Controls, cs)
	}
	return cov, nil
}

// ControlDetail is the evidence view of one control.
type ControlDetail struct {
	ControlStatus
	Mappings    []Mapping         `json:"mappings"`
	Evaluations []EvaluationView  `json:"evaluations"`
	Exceptions  []ExceptionView   `json:"exceptions"`
	History     []map[string]any  `json:"history"`
	Remediation map[string]string `json:"remediation"`
}

// EvaluationView is a stored evaluation with its run provenance.
type EvaluationView struct {
	Evaluation
	RunID              string    `json:"run_id"`
	Source             string    `json:"source"`
	EvaluatedAt        time.Time `json:"evaluated_at"`
	PolicyBundleSHA256 string    `json:"policy_bundle_sha256"`
	CatalogSHA256      string    `json:"catalog_sha256"`
}

// Control returns a control's status, mapped rules, latest evaluations
// (failures first), related exceptions and recent run history.
func (s *Service) Control(ctx context.Context, tenant, framework, control, scope string, staleAfter time.Duration) (ControlDetail, error) {
	f, ok := s.Catalog.Framework(framework)
	if !ok {
		return ControlDetail{}, ErrNotFound
	}
	title, ok := s.Catalog.ControlTitle(framework, control)
	if !ok {
		return ControlDetail{}, ErrNotFound
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return ControlDetail{}, err
	}
	runs, err := s.latestRuns(ctx, tenantID, scope)
	if err != nil {
		return ControlDetail{}, err
	}
	agg, err := s.aggregate(ctx, runs)
	if err != nil {
		return ControlDetail{}, err
	}
	d := ControlDetail{
		ControlStatus: s.controlStatus(f, Control{ID: control, Title: title}, agg, staleAfter, s.now()),
		Mappings:      s.Catalog.MappingsFor(framework, control),
		Evaluations:   []EvaluationView{}, Exceptions: []ExceptionView{}, History: []map[string]any{},
		Remediation: map[string]string{},
	}
	if d.Mappings == nil {
		d.Mappings = []Mapping{}
	}
	var rules []string
	for _, m := range d.Mappings {
		rules = append(rules, m.Rule)
		r, _ := s.Catalog.Rule(m.Rule)
		d.Remediation[m.Rule] = r.Remediation
	}
	if len(rules) == 0 {
		return d, nil
	}
	runIDs := make([]string, len(runs))
	for i, r := range runs {
		runIDs[i] = r.RunID
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT e.rule_id, e.subject_kind, e.subject, e.result, coalesce(e.exception_id::text, ''), e.message, e.evidence,
		       r.id, r.source, r.evaluated_at, r.policy_bundle_sha256, r.catalog_sha256
		FROM compliance_evaluations e JOIN compliance_runs r ON r.id = e.run_id
		WHERE e.run_id = ANY($1::uuid[]) AND e.rule_id = ANY($2)
		ORDER BY CASE e.result WHEN 'fail' THEN 0 WHEN 'excepted' THEN 1 ELSE 2 END, e.rule_id, e.subject
		LIMIT 500`, runIDs, rules)
	if err != nil {
		return ControlDetail{}, err
	}
	d.Evaluations, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (EvaluationView, error) {
		var v EvaluationView
		var ev []byte
		err := row.Scan(&v.RuleID, &v.SubjectKind, &v.Subject, &v.Result, &v.ExceptionID, &v.Message, &ev,
			&v.RunID, &v.Source, &v.EvaluatedAt, &v.PolicyBundleSHA256, &v.CatalogSHA256)
		if err == nil {
			err = json.Unmarshal(ev, &v.Evidence)
		}
		return v, err
	})
	if err != nil {
		return ControlDetail{}, err
	}
	all, err := s.listExceptions(ctx, tenantID, rules)
	if err != nil {
		return ControlDetail{}, err
	}
	d.Exceptions = all

	// Walk runs newest first and count only their evaluations of these rules,
	// so the cost is bounded by the 20 runs returned, not the whole history.
	rows, err = s.Pool.Query(ctx, `
		SELECT r.id, r.source, r.source_key, r.evaluated_at, c.pass, c.fail, c.excepted
		FROM compliance_runs r CROSS JOIN LATERAL (
			SELECT count(*) AS n, count(*) FILTER (WHERE e.result = 'pass') AS pass,
			       count(*) FILTER (WHERE e.result = 'fail') AS fail, count(*) FILTER (WHERE e.result = 'excepted') AS excepted
			FROM compliance_evaluations e WHERE e.run_id = r.id AND e.rule_id = ANY($2)) c
		WHERE r.tenant_id = $1 AND c.n > 0
		ORDER BY r.evaluated_at DESC LIMIT 20`, tenantID, rules)
	if err != nil {
		return ControlDetail{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, src, key string
		var at time.Time
		var p, fl, ex int
		if err := rows.Scan(&id, &src, &key, &at, &p, &fl, &ex); err != nil {
			return ControlDetail{}, err
		}
		d.History = append(d.History, map[string]any{"run_id": id, "source": src, "source_key": key, "evaluated_at": at,
			"pass": p, "fail": fl, "excepted": ex})
	}
	return d, rows.Err()
}

// -------------------------------------------------------------- exceptions

// ExceptionRequest asks for a time-bounded waiver.
type ExceptionRequest struct {
	RuleID        string    `json:"rule_id"`
	Subject       string    `json:"subject"`
	Justification string    `json:"justification"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// ExceptionView is the API representation of an exception.
type ExceptionView struct {
	ID            string     `json:"id"`
	RuleID        string     `json:"rule_id"`
	Subject       string     `json:"subject"`
	Justification string     `json:"justification"`
	Status        string     `json:"status"`
	Active        bool       `json:"active"`
	RequestedBy   string     `json:"requested_by"`
	DecidedBy     string     `json:"decided_by,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	DecidedAt     *time.Time `json:"decided_at,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
}

// RequestException validates and records an exception request.
func (s *Service) RequestException(ctx context.Context, tenant, actor string, req ExceptionRequest) (ExceptionView, error) {
	rule, ok := s.Catalog.Rule(req.RuleID)
	now := s.now()
	var problems []string
	if !ok {
		problems = append(problems, "unknown rule_id")
	}
	req.Subject = strings.TrimSpace(req.Subject)
	if req.Subject == "" || len(req.Subject) > 512 {
		problems = append(problems, "subject must be 1-512 characters (a resource ID, Terraform address or \"*\")")
	}
	if ok && req.Subject == "*" && rule.Severity == "critical" {
		problems = append(problems, "wildcard exceptions are not allowed for critical rules")
	}
	if n := len(strings.TrimSpace(req.Justification)); n < 20 || n > 2000 {
		problems = append(problems, "justification must be 20-2000 characters")
	}
	if !req.ExpiresAt.After(now) || req.ExpiresAt.Sub(now) > MaxExceptionLifetime {
		problems = append(problems, "expires_at must be in the future and at most 365 days away")
	}
	if len(problems) > 0 {
		return ExceptionView{}, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return ExceptionView{}, err
	}
	var id string
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO policy_exceptions (tenant_id, rule_id, subject, justification, requested_by, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, tenantID, req.RuleID, req.Subject, strings.TrimSpace(req.Justification),
			actor, req.ExpiresAt).Scan(&id); err != nil {
			return err
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "exception.request", TargetType: "policy_exception",
			TargetID: id, Outcome: "success", Details: map[string]any{"rule_id": req.RuleID, "subject": req.Subject,
				"expires_at": req.ExpiresAt.UTC().Format(time.RFC3339)}})
	})
	if err != nil {
		return ExceptionView{}, err
	}
	return s.getException(ctx, tenantID, id)
}

// Decisions on exceptions.
const (
	DecisionApprove = "approve"
	DecisionReject  = "reject"
	DecisionRevoke  = "revoke"
)

// exceptionTransitions maps a decision to its allowed {from, to} states.
var exceptionTransitions = map[string][2]string{
	DecisionApprove: {"requested", "approved"},
	DecisionReject:  {"requested", "rejected"},
	DecisionRevoke:  {"approved", "revoked"},
}

// DecideException approves, rejects or revokes an exception. Separation of
// duties: the requester can never approve or reject their own request; a
// denied attempt is itself audited.
func (s *Service) DecideException(ctx context.Context, tenant, actor, id, decision string) (ExceptionView, error) {
	if !uuidRe.MatchString(id) {
		return ExceptionView{}, ErrNotFound
	}
	transition, ok := exceptionTransitions[decision]
	from, to := transition[0], transition[1]
	if !ok {
		return ExceptionView{}, fmt.Errorf("%w: unknown decision", ErrInvalid)
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return ExceptionView{}, err
	}
	var denied bool
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var status, requestedBy string
		var expires time.Time
		err := tx.QueryRow(ctx, `SELECT status, requested_by, expires_at FROM policy_exceptions
			WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, id).Scan(&status, &requestedBy, &expires)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if status != from || (decision == DecisionApprove && !expires.After(s.now())) {
			return ErrConflict
		}
		if decision != DecisionRevoke && actor == requestedBy {
			denied = true
			return ErrSelfApproval
		}
		if _, err := tx.Exec(ctx, `UPDATE policy_exceptions SET status = $3, decided_by = $4, decided_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenantID, id, to, actor); err != nil {
			return err
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "exception." + decision,
			TargetType: "policy_exception", TargetID: id, Outcome: "success", Details: map[string]any{"from": from, "to": to}})
	})
	if denied {
		// Record the refused attempt in its own transaction (the main one rolled back).
		if aerr := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
			return audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "exception." + decision,
				TargetType: "policy_exception", TargetID: id, Outcome: "denied", Details: map[string]any{"reason": "self-approval"}})
		}); aerr != nil {
			logging.FromContext(ctx).Error("could not audit a refused self-approval", "actor", actor, "exception", id, "error", aerr)
		}
	}
	if err != nil {
		return ExceptionView{}, err
	}
	return s.getException(ctx, tenantID, id)
}

// ListExceptions lists a tenant's exceptions, newest first.
// ListExceptions returns one page of the tenant's exceptions, newest first,
// and the cursor of the next page ("" at the end).
func (s *Service) ListExceptions(ctx context.Context, tenant, after string, limit int) ([]ExceptionView, string, error) {
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return nil, "", err
	}
	at, id, hasCursor, err := paging.Decode(after)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrInvalid, paging.ErrBadCursor)
	}
	if hasCursor && !uuidRe.MatchString(id) {
		return nil, "", fmt.Errorf("%w: %w", ErrInvalid, paging.ErrBadCursor)
	}
	if !hasCursor {
		id = "00000000-0000-0000-0000-000000000000"
	}
	limit = paging.Limit(limit)
	rows, err := s.Pool.Query(ctx, `SELECT `+exceptionCols+` FROM policy_exceptions
		WHERE tenant_id = $1 AND (NOT $2 OR (created_at, id) < ($3, $4::uuid))
		ORDER BY created_at DESC, id DESC LIMIT $5`, tenantID, hasCursor, at, id, limit+1)
	if err != nil {
		return nil, "", err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ExceptionView])
	if err != nil {
		return nil, "", err
	}
	if out == nil {
		out = []ExceptionView{}
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = paging.Encode(out[len(out)-1].CreatedAt, out[len(out)-1].ID)
	}
	return out, next, nil
}

const exceptionCols = `id, rule_id, subject, justification, status,
	(status = 'approved' AND expires_at > now()), requested_by, coalesce(decided_by, ''), created_at, decided_at, expires_at`

func (s *Service) listExceptions(ctx context.Context, tenantID string, rules []string) ([]ExceptionView, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+exceptionCols+` FROM policy_exceptions
		WHERE tenant_id = $1 AND (cardinality($2::text[]) = 0 OR rule_id = ANY($2)) ORDER BY created_at DESC LIMIT 500`,
		tenantID, rules)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ExceptionView])
	if out == nil {
		out = []ExceptionView{}
	}
	return out, err
}

func (s *Service) getException(ctx context.Context, tenantID, id string) (ExceptionView, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+exceptionCols+` FROM policy_exceptions WHERE tenant_id = $1 AND id = $2`, tenantID, id)
	if err != nil {
		return ExceptionView{}, err
	}
	v, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[ExceptionView])
	if errors.Is(err, pgx.ErrNoRows) {
		return ExceptionView{}, ErrNotFound
	}
	return v, err
}

// ------------------------------------------------------------------- audit

// AuditEvents lists recent audit events for a tenant.
func (s *Service) AuditEvents(ctx context.Context, tenant string, limit int, beforeSeq int64) ([]audit.Record, error) {
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return nil, err
	}
	recs, err := audit.List(ctx, s.Pool, tenantID, limit, beforeSeq)
	if recs == nil {
		recs = []audit.Record{}
	}
	return recs, err
}

// VerifyAudit recomputes a tenant's audit hash chain.
func (s *Service) VerifyAudit(ctx context.Context, tenant string) (audit.Verification, error) {
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return audit.Verification{}, err
	}
	return audit.Verify(ctx, s.Pool, tenantID)
}

// AuditHashAt returns the stored hash of one audit event.
func (s *Service) AuditHashAt(ctx context.Context, tenant string, seq int64) (string, error) {
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return "", err
	}
	h, err := audit.HashAt(ctx, s.Pool, tenantID, seq)
	if errors.Is(err, audit.ErrNoEvent) {
		return "", ErrNotFound
	}
	return h, err
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
