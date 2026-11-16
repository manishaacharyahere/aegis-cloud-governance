package investigator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// RuleMeta is the catalog information attached to compliance evidence.
type RuleMeta struct {
	Title       string
	Severity    string
	Remediation string
}

// Errors.
var (
	ErrTenantNotFound = errors.New("tenant not found")
	ErrNotFound       = errors.New("not found")
	ErrInvalid        = errors.New("invalid request")
	ErrAmbiguous      = errors.New("resource_id exists in more than one account; set account_id")
)

const (
	listCap        = 20
	costWindowDays = 30
)

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func head(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

// collect gathers evidence about one resource. It must run inside a
// read-only transaction; every query is tenant-scoped.
func collect(ctx context.Context, tx pgx.Tx, tenantID, resourceID, account string, rules map[string]RuleMeta, now time.Time) (Bundle, error) {
	var (
		accountPK, accountExt, rtype, region, env, owner string
		tags                                             map[string]string
		cfg                                              map[string]any
		rels                                             []map[string]string
		version                                          int
		deletedAt                                        *time.Time
		updatedAt                                        time.Time
	)
	rows, err := tx.Query(ctx, `
		SELECT r.account_id, a.external_id, r.resource_type, r.region, r.environment, r.owner,
		       r.tags, r.configuration, r.relationships, r.current_version, r.deleted_at, r.updated_at
		FROM resources r JOIN cloud_accounts a ON a.id = r.account_id
		WHERE r.tenant_id = $1 AND r.resource_id = $2 AND ($3::text = '' OR a.external_id = $3)
		ORDER BY r.updated_at DESC LIMIT 2`, tenantID, resourceID, account)
	if err != nil {
		return Bundle{}, err
	}
	n := 0
	for rows.Next() {
		n++
		if n == 1 {
			if err := rows.Scan(&accountPK, &accountExt, &rtype, &region, &env, &owner, &tags, &cfg, &rels, &version, &deletedAt, &updatedAt); err != nil {
				rows.Close()
				return Bundle{}, err
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Bundle{}, err
	}
	switch {
	case n == 0:
		return Bundle{}, ErrNotFound
	case n > 1:
		return Bundle{}, ErrAmbiguous
	}

	b := Bundle{Subject: resourceID, Account: accountExt}
	config, truncated := boundedConfig(cfg)
	tagsAny := map[string]any{}
	for k, v := range tags {
		tagsAny[k] = v
	}
	if region == "" {
		region = "(none)"
	}
	facts := map[string]any{
		"resource_id": resourceID, "resource_type": rtype, "region": region, "environment": env, "owner": owner,
		"account": accountExt, "version": version, "updated_at": ts(updatedAt),
		"tags": scrub(tagsAny), "configuration": config, "configuration_truncated": truncated,
	}
	state := ""
	if deletedAt != nil {
		facts["deleted_at"] = ts(*deletedAt)
		state = fmt.Sprintf(" It was deleted from inventory at %s.", ts(*deletedAt))
	}
	b.add("resource", "resources", facts,
		"%s is a %s in region %s (environment %q, owner %q) in account %s, at inventory version %d, last updated %s.%s",
		resourceID, rtype, region, env, owner, accountExt, version, ts(updatedAt), state)

	if err := collectRelationships(ctx, tx, &b, tenantID, accountPK, rels); err != nil {
		return Bundle{}, err
	}
	if err := collectCompliance(ctx, tx, &b, tenantID, resourceID, rules, now); err != nil {
		return Bundle{}, err
	}
	if err := collectRisk(ctx, tx, &b, tenantID, resourceID); err != nil {
		return Bundle{}, err
	}
	if err := collectDrift(ctx, tx, &b, tenantID, accountPK, resourceID); err != nil {
		return Bundle{}, err
	}
	if err := collectCost(ctx, tx, &b, tenantID, resourceID, accountExt); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

func collectRelationships(ctx context.Context, tx pgx.Tx, b *Bundle, tenantID, accountPK string, out []map[string]string) error {
	rows, err := tx.Query(ctx, `SELECT relationship_type, source_resource_id FROM resource_relationships
		WHERE tenant_id = $1 AND account_id = $2 AND target_resource_id = $3 ORDER BY 1, 2 LIMIT 50`, tenantID, accountPK, b.Subject)
	if err != nil {
		return err
	}
	var incoming []string
	for rows.Next() {
		var typ, src string
		if err := rows.Scan(&typ, &src); err != nil {
			rows.Close()
			return err
		}
		incoming = append(incoming, src+" "+typ)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var outgoing []string
	for _, r := range out {
		outgoing = append(outgoing, r["type"]+" "+r["target_id"])
	}
	if len(outgoing)+len(incoming) == 0 {
		return nil
	}
	summary := fmt.Sprintf("It has %d outgoing and %d incoming relationships", len(outgoing), len(incoming))
	if len(outgoing) > 0 {
		summary += "; outgoing: " + strings.Join(head(outgoing, 5), ", ")
	}
	if len(incoming) > 0 {
		summary += "; incoming from: " + strings.Join(head(incoming, 5), ", ")
	}
	b.add("relationships", "resources.relationships, resource_relationships",
		map[string]any{"outgoing": head(outgoing, listCap), "incoming": head(incoming, listCap),
			"outgoing_count": len(outgoing), "incoming_count": len(incoming)}, "%s.", summary)
	return nil
}

func collectCompliance(ctx context.Context, tx pgx.Tx, b *Bundle, tenantID, subject string, rules map[string]RuleMeta, now time.Time) error {
	var runID string
	var at time.Time
	err := tx.QueryRow(ctx, `SELECT id, evaluated_at FROM compliance_runs WHERE tenant_id = $1 AND source = 'inventory'
		ORDER BY evaluated_at DESC, id LIMIT 1`, tenantID).Scan(&runID, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		b.add("compliance_run", "compliance_runs", map[string]any{"evaluated": false},
			"No inventory compliance evaluation has been run, so compliance status is unknown.")
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT rule_id, result, message FROM compliance_evaluations
		WHERE run_id = $1 AND tenant_id = $2 AND subject_kind = 'inventory_resource' AND subject = $3
		ORDER BY CASE result WHEN 'fail' THEN 0 WHEN 'excepted' THEN 1 ELSE 2 END, rule_id`, runID, tenantID, subject)
	if err != nil {
		return err
	}
	type ev struct{ rule, result, msg string }
	var evs []ev
	counts := map[string]int{"pass": 0, "fail": 0, "excepted": 0}
	for rows.Next() {
		var e ev
		if err := rows.Scan(&e.rule, &e.result, &e.msg); err != nil {
			rows.Close()
			return err
		}
		counts[e.result]++
		evs = append(evs, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	b.add("compliance_run", "compliance_runs/"+runID,
		map[string]any{"evaluated": true, "run_id": runID, "evaluated_at": ts(at), "rules_evaluated": len(evs),
			"pass": counts["pass"], "fail": counts["fail"], "excepted": counts["excepted"]},
		"In the latest inventory compliance run (%s at %s), %d rules applied to this resource: %d pass, %d fail, %d excepted.",
		runID, ts(at), len(evs), counts["pass"], counts["fail"], counts["excepted"])
	shown := 0
	for _, e := range evs {
		if e.result == "pass" || shown >= listCap {
			continue
		}
		shown++
		m := rules[e.rule]
		verb := "fails"
		if e.result == "excepted" {
			verb = "fails but is covered by an approved exception"
		}
		b.add("compliance_finding", "compliance_evaluations/"+runID,
			map[string]any{"rule_id": e.rule, "result": e.result, "message": e.msg, "title": m.Title,
				"severity": m.Severity, "remediation": m.Remediation},
			"Rule %s (%s; severity %s) %s: %s", e.rule, m.Title, m.Severity, verb, e.msg)
	}

	exRows, err := tx.Query(ctx, `SELECT id, rule_id, subject, status, requested_by, coalesce(decided_by, ''), expires_at
		FROM policy_exceptions WHERE tenant_id = $1 AND subject IN ($2, '*') ORDER BY created_at DESC LIMIT 10`, tenantID, subject)
	if err != nil {
		return err
	}
	defer exRows.Close()
	for exRows.Next() {
		var id, rule, subj, status, by, decidedBy string
		var exp time.Time
		if err := exRows.Scan(&id, &rule, &subj, &status, &by, &decidedBy, &exp); err != nil {
			return err
		}
		if status == "approved" && !exp.After(now) {
			status = "expired"
		}
		scope := "this resource"
		if subj == "*" {
			scope = "all resources"
		}
		b.add("exception", "policy_exceptions/"+id,
			map[string]any{"exception_id": id, "rule_id": rule, "subject": subj, "status": status,
				"requested_by": by, "decided_by": decidedBy, "expires_at": ts(exp)},
			"An exception to %s for %s is %s (requested by %q, expires %s).", rule, scope, status, by, ts(exp))
	}
	return exRows.Err()
}

func collectRisk(ctx context.Context, tx pgx.Tx, b *Bundle, tenantID, subject string) error {
	var runID, model string
	var at time.Time
	err := tx.QueryRow(ctx, `SELECT id, model_version, created_at FROM risk_runs WHERE tenant_id = $1
		ORDER BY created_at DESC, id LIMIT 1`, tenantID).Scan(&runID, &model, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT rule_id, score::float8, band, reasons, attack_path, blast_radius
		FROM risk_assessments WHERE run_id = $1 AND subject = $2 ORDER BY score DESC, rule_id LIMIT 10`, runID, subject)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := 0
	for rows.Next() {
		var rule, band string
		var score float64
		var reasons, blast []string
		var path []map[string]any
		if err := rows.Scan(&rule, &score, &band, &reasons, &path, &blast); err != nil {
			return err
		}
		found++
		text := fmt.Sprintf("Risk run %s (%s, model %s) scored the %s finding %.1f out of 100 (%s band)", runID, ts(at), model, rule, score, band)
		if len(reasons) > 0 {
			text += "; reasons: " + strings.Join(reasons, "; ")
		}
		if len(path) > 0 {
			text += fmt.Sprintf("; an internet attack path of %d hops reaches it", len(path))
		}
		if len(blast) > 0 {
			text += fmt.Sprintf("; %d other resources are in its blast radius", len(blast))
		}
		pathAny := make([]any, len(path))
		for i, h := range path {
			pathAny[i] = h
		}
		b.add("risk", "risk_assessments/"+runID,
			map[string]any{"run_id": runID, "rule_id": rule, "score": score, "band": band, "reasons": reasons,
				"attack_path": pathAny, "attack_path_hops": len(path), "blast_radius": head(blast, listCap),
				"blast_radius_count": len(blast), "model_version": model},
			"%s.", text)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if found == 0 {
		b.add("risk", "risk_runs/"+runID, map[string]any{"run_id": runID, "scored_findings": 0},
			"Risk run %s (%s) has no scored findings for this resource.", runID, ts(at))
	}
	return nil
}

func collectDrift(ctx context.Context, tx pgx.Tx, b *Bundle, tenantID, accountPK, resourceID string) error {
	var reportID string
	var at time.Time
	err := tx.QueryRow(ctx, `SELECT id, created_at FROM drift_reports WHERE tenant_id = $1 AND account_id = $2
		ORDER BY created_at DESC, id LIMIT 1`, tenantID, accountPK).Scan(&reportID, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT category, severity, changes, new_failures, resolved FROM drift_items
		WHERE report_id = $1 AND resource_id = $2 ORDER BY category`, reportID, resourceID)
	if err != nil {
		return err
	}
	defer rows.Close()
	found := 0
	for rows.Next() {
		var cat, sev string
		var changes []map[string]any
		var newFail, resolved []string
		if err := rows.Scan(&cat, &sev, &changes, &newFail, &resolved); err != nil {
			return err
		}
		found++
		var paths []string
		for _, c := range changes {
			paths = append(paths, fmt.Sprint(c["path"]))
		}
		text := fmt.Sprintf("Drift report %s (%s) found %s drift of %s severity", reportID, ts(at), cat, sev)
		if len(paths) > 0 {
			text += "; changed: " + strings.Join(head(paths, 8), ", ")
		}
		if len(newFail) > 0 {
			text += "; newly failing: " + strings.Join(newFail, ", ")
		}
		if len(resolved) > 0 {
			text += "; no longer failing: " + strings.Join(resolved, ", ")
		}
		b.add("drift", "drift_items/"+reportID,
			map[string]any{"report_id": reportID, "category": cat, "severity": sev, "changed_paths": head(paths, listCap),
				"new_failures": newFail, "resolved": resolved},
			"%s.", text)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if found == 0 {
		b.add("drift_clear", "drift_reports/"+reportID, map[string]any{"report_id": reportID},
			"Drift report %s (%s) found no drift on this resource.", reportID, ts(at))
	}
	return nil
}

func collectCost(ctx context.Context, tx pgx.Tx, b *Bundle, tenantID, resourceID, accountExt string) error {
	var lines int
	var total, cpu float64
	var from, to *time.Time
	var teams, methods string
	err := tx.QueryRow(ctx, `
		WITH last AS (SELECT max(usage_date) AS d FROM cost_records WHERE tenant_id = $1)
		SELECT count(*), coalesce(sum(cost_usd), 0)::float8, min(usage_date), max(usage_date),
		       coalesce(avg(cpu_utilization), -1)::float8,
		       coalesce(string_agg(DISTINCT CASE WHEN team = '' THEN '(unallocated)' ELSE team END, ', '), ''),
		       coalesce(string_agg(DISTINCT allocation_method, ', '), '')
		FROM cost_records c, last
		WHERE c.tenant_id = $1 AND c.resource_id = $2 AND c.account_id = $3 AND c.usage_date > last.d - $4::int`,
		tenantID, resourceID, accountExt, costWindowDays).Scan(&lines, &total, &from, &to, &cpu, &teams, &methods)
	if err != nil {
		return err
	}
	if lines > 0 {
		facts := map[string]any{"window_days": costWindowDays, "total_usd": round2(total), "cost_lines": lines,
			"from": from.Format(time.DateOnly), "to": to.Format(time.DateOnly), "team": teams, "allocation_method": methods}
		text := fmt.Sprintf("Imported cost for this resource in the %d days to %s: $%.2f across %d cost lines (from %s), allocated to %s by %s",
			costWindowDays, to.Format(time.DateOnly), round2(total), lines, from.Format(time.DateOnly), teams, methods)
		if cpu >= 0 {
			facts["avg_cpu_percent"] = math.Round(cpu*10) / 10
			text += fmt.Sprintf("; average CPU %.1f%%", math.Round(cpu*10)/10)
		}
		b.add("cost", "cost_records", facts, "%s.", text)
	}

	rows, err := tx.Query(ctx, `SELECT id, kind, status, projected_monthly_savings::float8, as_of, details
		FROM recommendations WHERE tenant_id = $1 AND resource_id = $2 ORDER BY created_at DESC, id LIMIT 10`, tenantID, resourceID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, kind, status string
		var saving float64
		var asOf time.Time
		var details map[string]any
		if err := rows.Scan(&id, &kind, &status, &saving, &asOf, &details); err != nil {
			return err
		}
		raw, _ := json.Marshal(details)
		if len(raw) > 1024 {
			details = map[string]any{"truncated": true}
		}
		b.add("recommendation", "recommendations/"+id,
			map[string]any{"recommendation_id": id, "kind": kind, "status": status, "projected_monthly_usd": saving,
				"as_of": asOf.Format(time.DateOnly), "details": details},
			"A %s recommendation (status %s, as of %s) projects savings of $%.2f per month.", kind, status, asOf.Format(time.DateOnly), saving)
	}
	return rows.Err()
}
