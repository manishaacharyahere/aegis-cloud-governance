package drift

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/tenancy"
)

// Errors.
var (
	ErrTenantNotFound = errors.New("tenant not found")
	ErrNotFound       = errors.New("not found")
	ErrNoBaseline     = errors.New("no approved baseline for this account; approve one first")
	ErrAmbiguous      = errors.New("tenant has several accounts; account_id is required")
	ErrNoInventory    = errors.New("account has no inventory")
	ErrInvalid        = errors.New("invalid request")
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Service is the drift module.
type Service struct {
	Pool         *pgxpool.Pool
	OPA          *opa.Client
	Config       Config
	RuleSeverity map[string]string // from the compliance catalog
}

// Baseline is an approved state.
type Baseline struct {
	ID            string    `json:"id"`
	AccountID     string    `json:"account_id"`
	ImportID      string    `json:"import_id"`
	Status        string    `json:"status"`
	ApprovedBy    string    `json:"approved_by"`
	Note          string    `json:"note"`
	ResourceCount int       `json:"resource_count"`
	ContentSHA256 string    `json:"content_sha256"`
	CreatedAt     time.Time `json:"created_at"`
}

// Report is a stored drift comparison.
type Report struct {
	ID                 string         `json:"id"`
	AccountID          string         `json:"account_id"`
	BaselineID         string         `json:"baseline_id"`
	ObservedImportID   string         `json:"observed_import_id"`
	ConfigSHA256       string         `json:"config_sha256"`
	PolicyBundleSHA256 string         `json:"policy_bundle_sha256"`
	Actor              string         `json:"actor"`
	Counts             map[string]any `json:"counts"`
	CreatedAt          time.Time      `json:"created_at"`
	Items              []Item         `json:"items"`
}

func (s *Service) scope(ctx context.Context, tenant, accountID string) (tenantID, account string, err error) {
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, tenant).Scan(&tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrTenantNotFound
		}
		return "", "", err
	}
	if accountID != "" {
		if !uuidRe.MatchString(accountID) {
			return "", "", ErrNotFound
		}
		err := s.Pool.QueryRow(ctx, `SELECT id FROM cloud_accounts WHERE tenant_id = $1 AND id = $2`, tenantID, accountID).Scan(&account)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrNotFound
		}
		return tenantID, account, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT id FROM cloud_accounts WHERE tenant_id = $1 LIMIT 2`, tenantID)
	if err != nil {
		return "", "", err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return "", "", err
	}
	switch len(ids) {
	case 0:
		return "", "", ErrNoInventory
	case 1:
		return tenantID, ids[0], nil
	default:
		return "", "", ErrAmbiguous
	}
}

type liveResource struct {
	State
	sha string
}

func (s *Service) observed(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, tenantID, account string) (map[string]liveResource, error) {
	rows, err := q.Query(ctx, `SELECT resource_id, resource_type, region, environment, owner, tags, configuration, content_sha256
		FROM resources WHERE tenant_id = $1 AND account_id = $2 AND deleted_at IS NULL`, tenantID, account)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]liveResource{}
	for rows.Next() {
		var r liveResource
		var tags, cfg []byte
		if err := rows.Scan(&r.ResourceID, &r.Type, &r.Region, &r.Environment, &r.Owner, &tags, &cfg, &r.sha); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(tags, &r.Tags); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(cfg, &r.Configuration); err != nil {
			return nil, err
		}
		out[r.ResourceID] = r
	}
	return out, rows.Err()
}

// ApproveBaseline records the account's current observed inventory as the
// approved state, superseding any previous baseline.
func (s *Service) ApproveBaseline(ctx context.Context, tenant, accountID, actor, note string) (Baseline, error) {
	if len(note) > 1000 {
		return Baseline{}, fmt.Errorf("%w: note longer than 1000 characters", ErrInvalid)
	}
	tenantID, account, err := s.scope(ctx, tenant, accountID)
	if err != nil {
		return Baseline{}, err
	}
	var b Baseline
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// Serialise with imports for this account so the copy is consistent.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM cloud_accounts WHERE id = $1 FOR UPDATE`, account); err != nil {
			return err
		}
		var importID string
		err := tx.QueryRow(ctx, `SELECT id FROM inventory_imports WHERE tenant_id = $1 AND account_id = $2
			ORDER BY captured_at DESC LIMIT 1`, tenantID, account).Scan(&importID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoInventory
		}
		if err != nil {
			return err
		}
		live, err := s.observed(ctx, tx, tenantID, account)
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(live))
		for id := range live {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		h := sha256.New()
		rows := make([][]any, 0, len(ids))
		for _, id := range ids {
			fmt.Fprintf(h, "%s\x00%s\x00", id, live[id].sha)
			st, _ := json.Marshal(live[id].State)
			rows = append(rows, []any{nil, id, live[id].Type, st})
		}
		if _, err := tx.Exec(ctx, `UPDATE drift_baselines SET status = 'superseded'
			WHERE tenant_id = $1 AND account_id = $2 AND status = 'active'`, tenantID, account); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO drift_baselines (tenant_id, account_id, import_id, approved_by, note, resource_count, content_sha256)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id, account_id, import_id, status, approved_by, note, resource_count, content_sha256, created_at`,
			tenantID, account, importID, actor, note, len(ids), hex.EncodeToString(h.Sum(nil))).Scan(
			&b.ID, &b.AccountID, &b.ImportID, &b.Status, &b.ApprovedBy, &b.Note, &b.ResourceCount, &b.ContentSHA256, &b.CreatedAt); err != nil {
			return err
		}
		for _, r := range rows {
			r[0] = b.ID
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"drift_baseline_resources"},
			[]string{"baseline_id", "resource_id", "resource_type", "state"}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "drift.baseline.approve", TargetType: "drift_baseline",
			TargetID: b.ID, Outcome: "success", Details: map[string]any{"account_id": account, "import_id": importID,
				"resources": len(ids), "content_sha256": b.ContentSHA256}})
	})
	return b, err
}

// Compare diffs the active baseline against the current observed inventory,
// evaluating both sides with the same policy bundle, and stores the report.
func (s *Service) Compare(ctx context.Context, tenant, accountID, actor string) (Report, error) {
	tenantID, account, err := s.scope(ctx, tenant, accountID)
	if err != nil {
		return Report{}, err
	}
	var baselineID string
	err = s.Pool.QueryRow(ctx, `SELECT id FROM drift_baselines WHERE tenant_id = $1 AND account_id = $2 AND status = 'active'`,
		tenantID, account).Scan(&baselineID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Report{}, ErrNoBaseline
	}
	if err != nil {
		return Report{}, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT state FROM drift_baseline_resources WHERE baseline_id = $1`, baselineID)
	if err != nil {
		return Report{}, err
	}
	approved := map[string]State{}
	for rows.Next() {
		var raw []byte
		var st State
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return Report{}, err
		}
		if err := json.Unmarshal(raw, &st); err != nil {
			rows.Close()
			return Report{}, err
		}
		approved[st.ResourceID] = st
	}
	rows.Close()
	live, err := s.observed(ctx, s.Pool, tenantID, account)
	if err != nil {
		return Report{}, err
	}
	observed := make(map[string]State, len(live))
	for id, r := range live {
		observed[id] = r.State
	}
	var importID string
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM inventory_imports WHERE tenant_id = $1 AND account_id = $2
		ORDER BY captured_at DESC LIMIT 1`, tenantID, account).Scan(&importID); err != nil {
		return Report{}, err
	}

	bundle, err := s.OPA.Bundle(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("policy bundle: %w", err)
	}
	pcfg, err := tenancy.Load(ctx, s.Pool, tenantID)
	if err != nil {
		return Report{}, err
	}
	approvedFail, err := s.failures(ctx, approved, pcfg.Input())
	if err != nil {
		return Report{}, err
	}
	observedFail, err := s.failures(ctx, observed, pcfg.Input())
	if err != nil {
		return Report{}, err
	}
	items := Compare(s.Config, approved, observed, approvedFail, observedFail, s.RuleSeverity)

	counts := map[string]any{"total": len(items), "by_category": map[string]int{}, "by_severity": map[string]int{},
		"approved_resources": len(approved), "observed_resources": len(observed)}
	for _, it := range items {
		counts["by_category"].(map[string]int)[it.Category]++
		counts["by_severity"].(map[string]int)[it.Severity]++
	}

	rep := Report{AccountID: account, BaselineID: baselineID, ObservedImportID: importID, ConfigSHA256: s.Config.SHA256(),
		PolicyBundleSHA256: bundle.SHA256, Actor: actor, Counts: counts, Items: items}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO policy_bundles (sha256, modules) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			bundle.SHA256, mustJSON(bundle.Modules)); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO drift_reports (tenant_id, account_id, baseline_id, observed_import_id,
			config_sha256, policy_bundle_sha256, actor, counts) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, created_at`,
			tenantID, account, baselineID, importID, rep.ConfigSHA256, bundle.SHA256, actor, mustJSON(counts)).Scan(&rep.ID, &rep.CreatedAt); err != nil {
			return err
		}
		rows := make([][]any, 0, len(items))
		for _, it := range items {
			rows = append(rows, []any{rep.ID, it.ResourceID, it.ResourceType, it.Category, it.Severity,
				mustJSON(nonNil(it.Changes)), nonNilS(it.NewFailures), nonNilS(it.Resolved)})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"drift_items"},
			[]string{"report_id", "resource_id", "resource_type", "category", "severity", "changes", "new_failures", "resolved"},
			pgx.CopyFromRows(rows)); err != nil {
			return err
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "drift.compare", TargetType: "drift_report",
			TargetID: rep.ID, Outcome: "success", Details: map[string]any{"baseline_id": baselineID, "items": len(items)}})
	})
	if rep.Items == nil {
		rep.Items = []Item{}
	}
	return rep, err
}

// failures evaluates states with the inventory policies and returns the
// failing rule IDs per resource.
func (s *Service) failures(ctx context.Context, states map[string]State, policyConfig map[string]any) (map[string][]string, error) {
	docs := make([]map[string]any, 0, len(states))
	for _, st := range states {
		docs = append(docs, map[string]any{"id": st.ResourceID, "type": st.Type, "region": st.Region,
			"tags": st.Tags, "configuration": st.Configuration})
	}
	type finding struct {
		RuleID  string `json:"rule_id"`
		Address string `json:"address"`
	}
	out := map[string][]string{}
	if len(docs) == 0 {
		return out, nil
	}
	for _, chunk := range opa.Chunks(docs, opa.ChunkSize) {
		var res struct {
			Deny []finding `json:"deny"`
			Warn []finding `json:"warn"`
		}
		if err := s.OPA.Query(ctx, "aegis.inventory", map[string]any{"resources": chunk, "config": policyConfig}, &res); err != nil {
			return nil, fmt.Errorf("evaluate policies: %w", err)
		}
		for _, f := range append(res.Deny, res.Warn...) {
			out[f.Address] = append(out[f.Address], f.RuleID)
		}
	}
	return out, nil
}

// GetReport returns a stored report; items may be filtered by category or minimum severity.
func (s *Service) GetReport(ctx context.Context, tenant, id, category, minSeverity string) (Report, error) {
	if !uuidRe.MatchString(id) {
		return Report{}, ErrNotFound
	}
	if minSeverity != "" && !ValidSeverity(minSeverity) {
		return Report{}, fmt.Errorf("%w: unknown severity %q", ErrInvalid, minSeverity)
	}
	if category != "" {
		if _, ok := categoryRank[category]; !ok {
			return Report{}, fmt.Errorf("%w: unknown category %q", ErrInvalid, category)
		}
	}
	var tenantID string
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, tenant).Scan(&tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Report{}, ErrTenantNotFound
		}
		return Report{}, err
	}
	var r Report
	var counts []byte
	err := s.Pool.QueryRow(ctx, `SELECT id, account_id, baseline_id, observed_import_id, config_sha256, policy_bundle_sha256,
		actor, counts, created_at FROM drift_reports WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(
		&r.ID, &r.AccountID, &r.BaselineID, &r.ObservedImportID, &r.ConfigSHA256, &r.PolicyBundleSHA256, &r.Actor, &counts, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Report{}, ErrNotFound
	}
	if err != nil {
		return Report{}, err
	}
	_ = json.Unmarshal(counts, &r.Counts)
	maxRank := 3
	if minSeverity != "" {
		maxRank = sevRank[minSeverity]
	}
	var sevs []string
	for sv, rank := range sevRank {
		if rank <= maxRank {
			sevs = append(sevs, sv)
		}
	}
	rows, err := s.Pool.Query(ctx, `SELECT resource_id, resource_type, category, severity, changes, new_failures, resolved
		FROM drift_items WHERE report_id = $1 AND ($2 = '' OR category = $2) AND severity = ANY($3)`, id, category, sevs)
	if err != nil {
		return Report{}, err
	}
	r.Items, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Item, error) {
		var it Item
		var ch []byte
		err := row.Scan(&it.ResourceID, &it.ResourceType, &it.Category, &it.Severity, &ch, &it.NewFailures, &it.Resolved)
		if err == nil {
			err = json.Unmarshal(ch, &it.Changes)
		}
		return it, err
	})
	if err != nil {
		return Report{}, err
	}
	sort.Slice(r.Items, func(i, j int) bool {
		a, b := r.Items[i], r.Items[j]
		if sevRank[a.Severity] != sevRank[b.Severity] {
			return sevRank[a.Severity] < sevRank[b.Severity]
		}
		if categoryRank[a.Category] != categoryRank[b.Category] {
			return categoryRank[a.Category] < categoryRank[b.Category]
		}
		return a.ResourceID < b.ResourceID
	})
	if r.Items == nil {
		r.Items = []Item{}
	}
	return r, nil
}

// ListBaselines lists a tenant's baselines, newest first.
func (s *Service) ListBaselines(ctx context.Context, tenant string) ([]Baseline, error) {
	var tenantID string
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, tenant).Scan(&tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTenantNotFound
		}
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT id, account_id, import_id, status, approved_by, note, resource_count, content_sha256, created_at
		FROM drift_baselines WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 100`, tenantID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Baseline])
	if out == nil {
		out = []Baseline{}
	}
	return out, err
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func nonNil(c []PathChange) []PathChange {
	if c == nil {
		return []PathChange{}
	}
	return c
}

func nonNilS(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ValidSeverity reports whether s is a drift severity.
func ValidSeverity(s string) bool { _, ok := sevRank[strings.ToLower(s)]; return ok }
