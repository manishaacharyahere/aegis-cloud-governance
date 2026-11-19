package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/paging"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/signing"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/tenancy"
)

// Errors.
var (
	ErrTenantNotFound = errors.New("tenant not found")
	ErrNotFound       = errors.New("not found")
	ErrAmbiguous      = errors.New("resource_id exists in more than one account; set account_id")
	ErrConflict       = errors.New("conflict")
	// ErrDelivery: the pull request could not be opened (the cause is wrapped).
	ErrDelivery    = errors.New("delivering the change set failed")
	ErrForbidden   = errors.New("not allowed")
	ErrStale       = errors.New("the resource changed after this remediation was simulated; it is now stale and must be proposed again")
	ErrNotObserved = errors.New("no inventory import has changed the resource since release; import the current inventory, then verify")
)

// Statuses.
const (
	StatusBlocked            = "blocked"
	StatusPending            = "pending_approval"
	StatusApproved           = "approved"
	StatusRejected           = "rejected"
	StatusStale              = "stale"
	StatusReleased           = "released"
	StatusVerified           = "verified"
	StatusVerificationFailed = "verification_failed"
)

// Policy is what the simulation needs from OPA.
type Policy = opa.Querier

// Service is Module H.
type Service struct {
	Pool   *pgxpool.Pool
	OPA    Policy
	Now    func() time.Time
	Signer *signing.Signer // signs released change sets (nil: unsigned)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Simulation is the deterministic evidence an approver decides on.
type Simulation struct {
	Before         []string `json:"failing_before"`
	After          []string `json:"failing_after"`
	Resolved       []string `json:"resolved"`
	Introduced     []string `json:"introduced"`
	TargetRule     string   `json:"target_rule,omitempty"`
	TargetResolved bool     `json:"target_resolved"`
	Passed         bool     `json:"passed"`
	BlockedReasons []string `json:"blocked_reasons"`
	Diff           []Change `json:"diff"`
	Impact         Impact   `json:"impact"`
	Notes          []string `json:"notes"`
	Environment    string   `json:"environment"`
}

// Impact lists resources connected to the one being changed.
type Impact struct {
	Incoming []string `json:"incoming"` // "<source> <relationship>"
	Outgoing []string `json:"outgoing"` // "<relationship> <target>"
}

// Approval is one decision.
type Approval struct {
	Actor      string    `json:"actor"`
	Decision   string    `json:"decision"`
	PlanSHA256 string    `json:"plan_sha256"`
	Comment    string    `json:"comment"`
	CreatedAt  time.Time `json:"created_at"`
}

// View is a stored remediation.
type View struct {
	ID                string     `json:"id"`
	Source            string     `json:"source"`
	RuleID            string     `json:"rule_id,omitempty"`
	ResourceID        string     `json:"resource_id"`
	AccountID         string     `json:"account_id"`
	Operations        []Op       `json:"operations"`
	Justification     string     `json:"justification"`
	RequestedBy       string     `json:"requested_by"`
	Status            string     `json:"status"`
	RequiredApprovals int        `json:"required_approvals"`
	Disruptive        bool       `json:"disruptive"`
	Simulation        Simulation `json:"simulation"`
	PlanSHA256        string     `json:"plan_sha256"`
	ResourceVersion   int        `json:"resource_version"`
	PolicyBundleSHA   string     `json:"policy_bundle_sha256"`
	CreatedAt         time.Time  `json:"created_at"`
	ReleasedAt        *time.Time `json:"released_at,omitempty"`
	ReleasedBy        string     `json:"released_by,omitempty"`
	StaleReason       string     `json:"stale_reason,omitempty"`
	// The resource as the latest inventory import shows it, so a reader can
	// tell whether verification has anything new to check.
	ObservedVersion   int             `json:"observed_version,omitempty"`
	ObservedUpdatedAt *time.Time      `json:"observed_updated_at,omitempty"`
	VerifiedAt        *time.Time      `json:"verified_at,omitempty"`
	Verification      json.RawMessage `json:"verification,omitempty"`
	Approvals         []Approval      `json:"approvals"`
	ChangeSet         *ChangeSet      `json:"change_set,omitempty"`
	// PullRequestURL is where the released change set was delivered (GitHub).
	PullRequestURL string `json:"pull_request_url,omitempty"`
}

// ChangeSet is what a released remediation hands to the change pipeline.
type ChangeSet struct {
	PlanSHA256   string   `json:"plan_sha256"`
	ResourceID   string   `json:"resource_id"`
	AccountID    string   `json:"account_id"`
	NativeType   string   `json:"native_type"`
	Operations   []Op     `json:"operations"`
	Diff         []Change `json:"diff"`
	Instructions string   `json:"instructions"`
	// Signed is the Ed25519-signed change-set payload; verify it with
	// GET /api/v1/signing-key and `go run ./cmd/aegis-verify`.
	Signed *signing.Signed `json:"signed,omitempty"`
}

// signedChangeSet is what a pipeline verifies before applying a change.
type signedChangeSet struct {
	Type          string   `json:"type"`
	RemediationID string   `json:"remediation_id"`
	PlanSHA256    string   `json:"plan_sha256"`
	RuleID        string   `json:"rule_id,omitempty"`
	ResourceID    string   `json:"resource_id"`
	AccountID     string   `json:"account_id"`
	NativeType    string   `json:"native_type"`
	Operations    []Op     `json:"operations"`
	RequestedBy   string   `json:"requested_by"`
	ApprovedBy    []string `json:"approved_by"`
	ReleasedBy    string   `json:"released_by"`
	ReleasedAt    string   `json:"released_at"`
}

const releaseInstructions = "Apply this change through your normal change pipeline (update the Terraform " +
	"configuration and run plan/apply there, with its own review). Aegis has not changed any cloud resource. " +
	"After the change is live, import the inventory again and call verify."

// ProposeRequest creates a remediation.
type ProposeRequest struct {
	Source        string `json:"source"` // finding | manual
	RuleID        string `json:"rule_id"`
	ResourceID    string `json:"resource_id"`
	AccountID     string `json:"account_id"`
	Operations    []Op   `json:"operations"`
	Justification string `json:"justification"`
}

type resource struct {
	pk, account, id, nativeType, env, sha string
	version                               int
	deleted                               bool
	state                                 State
	outgoing                              []map[string]string
}

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

const resourceCols = `r.id, a.external_id, r.resource_id, r.resource_type, r.native_type, r.region, r.environment,
	r.tags, r.configuration, r.relationships, r.current_version, r.content_sha256, r.deleted_at IS NOT NULL`

func scanResources(rows pgx.Rows) ([]resource, error) {
	defer rows.Close()
	var out []resource
	for rows.Next() {
		var r resource
		if err := rows.Scan(&r.pk, &r.account, &r.id, &r.state.Type, &r.nativeType, &r.state.Region, &r.env,
			&r.state.Tags, &r.state.Configuration, &r.outgoing, &r.version, &r.sha, &r.deleted); err != nil {
			return nil, err
		}
		r.state.ID = r.id
		out = append(out, r)
	}
	return out, rows.Err()
}

func loadResource(ctx context.Context, q querier, tenantID, resourceID, account string) (resource, error) {
	rows, err := q.Query(ctx, `SELECT `+resourceCols+` FROM resources r JOIN cloud_accounts a ON a.id = r.account_id
		WHERE r.tenant_id = $1 AND r.resource_id = $2 AND ($3::text = '' OR a.external_id = $3) LIMIT 2`, tenantID, resourceID, account)
	if err != nil {
		return resource{}, err
	}
	rs, err := scanResources(rows)
	switch {
	case err != nil:
		return resource{}, err
	case len(rs) == 0:
		return resource{}, ErrNotFound
	case len(rs) > 1:
		return resource{}, ErrAmbiguous
	}
	return rs[0], nil
}

func loadByPK(ctx context.Context, q querier, tenantID, pk string) (resource, error) {
	return loadByPKLock(ctx, q, tenantID, pk, "")
}

// loadByPKLock optionally locks the resource row (lock "FOR SHARE OF r"), so an
// import cannot change it between a freshness check and the commit.
func loadByPKLock(ctx context.Context, q querier, tenantID, pk, lock string) (resource, error) {
	rows, err := q.Query(ctx, `SELECT `+resourceCols+` FROM resources r JOIN cloud_accounts a ON a.id = r.account_id
		WHERE r.tenant_id = $1 AND r.id = $2 `+lock, tenantID, pk)
	if err != nil {
		return resource{}, err
	}
	rs, err := scanResources(rows)
	if err != nil {
		return resource{}, err
	}
	if len(rs) == 0 {
		return resource{}, ErrNotFound
	}
	return rs[0], nil
}

// failing evaluates the inventory policies on one state and returns the
// sorted IDs of rules it fails (deny and warn).
func (s *Service) failing(ctx context.Context, st State, policyConfig map[string]any) ([]string, error) {
	findings, err := opa.EvaluateInventory(ctx, s.OPA, []opa.Resource{st}, policyConfig)
	if err != nil {
		return nil, err
	}
	if out := opa.FailingRules(findings)[st.ID]; out != nil {
		return out, nil
	}
	return []string{}, nil
}

func minus(a, b []string) []string {
	out := []string{}
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

// simulate applies ops to a copy and compares policy results before and after.
func (s *Service) simulate(ctx context.Context, r resource, ops []Op, target string, policyConfig map[string]any) (Simulation, error) {
	after, diff, err := Apply(r.state, ops)
	if err != nil {
		return Simulation{}, err
	}
	before, err := s.failing(ctx, r.state, policyConfig)
	if err != nil {
		return Simulation{}, err
	}
	afterFail, err := s.failing(ctx, after, policyConfig)
	if err != nil {
		return Simulation{}, err
	}
	sim := Simulation{Before: before, After: afterFail, Resolved: minus(before, afterFail), Introduced: minus(afterFail, before),
		TargetRule: target, Diff: diff, BlockedReasons: []string{}, Notes: []string{}, Environment: r.env}
	if sim.Diff == nil {
		sim.Diff = []Change{}
	}
	sim.TargetResolved = target != "" && slices.Contains(sim.Resolved, target)
	if len(diff) == 0 {
		sim.BlockedReasons = append(sim.BlockedReasons, "the operations do not change the resource")
	}
	if len(sim.Introduced) > 0 {
		sim.BlockedReasons = append(sim.BlockedReasons, "introduces failing rules: "+strings.Join(sim.Introduced, ", "))
	}
	if target != "" && !sim.TargetResolved {
		sim.BlockedReasons = append(sim.BlockedReasons, target+" still fails after the change")
	}
	sim.Passed = len(sim.BlockedReasons) == 0
	return sim, nil
}

func planSHA(r resource, ops []Op, bundleSHA, configSHA string) string {
	raw, _ := json.Marshal(map[string]any{"resource_pk": r.pk, "version": r.version, "content_sha256": r.sha,
		"operations": ops, "policy_bundle_sha256": bundleSHA, "policy_config_sha256": configSHA})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *Service) tenantID(ctx context.Context, slug string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, slug).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTenantNotFound
	}
	return id, err
}

func (s *Service) impact(ctx context.Context, tenantID string, r resource) (Impact, error) {
	imp := Impact{Incoming: []string{}, Outgoing: []string{}}
	for _, o := range r.outgoing {
		imp.Outgoing = append(imp.Outgoing, o["type"]+" "+o["target_id"])
	}
	rows, err := s.Pool.Query(ctx, `SELECT source_resource_id, relationship_type FROM resource_relationships rr
		JOIN cloud_accounts a ON a.id = rr.account_id
		WHERE rr.tenant_id = $1 AND a.external_id = $2 AND rr.target_resource_id = $3 ORDER BY 1, 2 LIMIT 100`, tenantID, r.account, r.id)
	if err != nil {
		return imp, err
	}
	defer rows.Close()
	for rows.Next() {
		var src, typ string
		if err := rows.Scan(&src, &typ); err != nil {
			return imp, err
		}
		imp.Incoming = append(imp.Incoming, src+" "+typ)
	}
	return imp, rows.Err()
}

var accountRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

// Propose simulates a remediation and stores it as pending_approval (passed)
// or blocked (failed). Blocked remediations are kept as evidence.
func (s *Service) Propose(ctx context.Context, tenant, actor string, req ProposeRequest) (View, error) {
	req.Justification = strings.TrimSpace(req.Justification)
	var problems []string
	if n := len([]rune(req.Justification)); n < 10 || n > 2000 {
		problems = append(problems, "justification must be 10-2000 characters")
	}
	if n := len(req.ResourceID); n == 0 || n > 512 {
		problems = append(problems, "resource_id must be 1-512 characters")
	}
	if req.AccountID != "" && !accountRe.MatchString(req.AccountID) {
		problems = append(problems, "invalid account_id")
	}
	switch req.Source {
	case "finding":
		if req.RuleID == "" || len(req.Operations) > 0 {
			problems = append(problems, "a finding remediation needs rule_id and no operations (they come from the rule's template)")
		}
	case "manual":
		if req.RuleID != "" {
			problems = append(problems, "a manual remediation has no rule_id")
		}
	default:
		problems = append(problems, "source must be finding or manual")
	}
	if len(problems) > 0 {
		return View{}, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return View{}, err
	}
	r, err := loadResource(ctx, s.Pool, tenantID, req.ResourceID, req.AccountID)
	if err != nil {
		return View{}, err
	}
	if r.deleted {
		return View{}, fmt.Errorf("%w: the resource is deleted in the latest inventory", ErrInvalid)
	}

	ops := req.Operations
	var tmpl Template
	if req.Source == "finding" {
		if tmpl, ops, err = FromTemplate(req.RuleID, r.state); err != nil {
			return View{}, err
		}
	} else if err := ValidateOps(ops); err != nil {
		return View{}, err
	}
	bundle, err := s.OPA.Bundle(ctx)
	if err != nil {
		return View{}, fmt.Errorf("policy bundle: %w", err)
	}
	pcfg, err := tenancy.Load(ctx, s.Pool, tenantID)
	if err != nil {
		return View{}, err
	}
	sim, err := s.simulate(ctx, r, ops, req.RuleID, pcfg.Input())
	if err != nil {
		return View{}, err
	}
	if req.Source == "finding" && !slices.Contains(sim.Before, req.RuleID) {
		return View{}, fmt.Errorf("%w: %s does not currently fail on %s", ErrConflict, req.RuleID, r.id)
	}
	if sim.Impact, err = s.impact(ctx, tenantID, r); err != nil {
		return View{}, err
	}
	if tmpl.Note != "" {
		sim.Notes = append(sim.Notes, tmpl.Note)
	}
	required := 1
	if r.env == "production" {
		required++
		sim.Notes = append(sim.Notes, "Production resource: one extra approval required.")
	}
	if tmpl.Disruptive {
		required++
		sim.Notes = append(sim.Notes, "Disruptive change: one extra approval required.")
	}
	status := StatusPending
	if !sim.Passed {
		status = StatusBlocked
	}
	v := View{Source: req.Source, RuleID: req.RuleID, ResourceID: r.id, AccountID: r.account, Operations: ops,
		Justification: req.Justification, RequestedBy: actor, Status: status, RequiredApprovals: required,
		Disruptive: tmpl.Disruptive, Simulation: sim, PlanSHA256: planSHA(r, ops, bundle.SHA256, pcfg.SHA256()),
		ResourceVersion: r.version, PolicyBundleSHA: bundle.SHA256, Approvals: []Approval{}}
	opsJSON, _ := json.Marshal(ops)
	simJSON, _ := json.Marshal(sim)
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO remediations (tenant_id, source, rule_id, resource_pk, resource_id, account_id,
			operations, justification, requested_by, status, required_approvals, disruptive, simulation, plan_sha256,
			resource_version, resource_sha256, policy_bundle_sha, policy_config_sha256)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING id, created_at`,
			tenantID, req.Source, req.RuleID, r.pk, r.id, r.account, opsJSON, req.Justification, actor, status, required,
			tmpl.Disruptive, simJSON, v.PlanSHA256, r.version, r.sha, bundle.SHA256, pcfg.SHA256()).Scan(&v.ID, &v.CreatedAt); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return fmt.Errorf("%w: an open remediation for %s on this resource already exists", ErrConflict, req.RuleID)
			}
			return err
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{Actor: actor, Action: "remediation.proposed", TargetType: "remediation",
			TargetID: v.ID, Outcome: "success", Details: map[string]any{"resource_id": r.id, "rule_id": req.RuleID,
				"status": status, "plan_sha256": v.PlanSHA256, "introduced": sim.Introduced, "resolved": sim.Resolved}})
	})
	if err != nil {
		return View{}, err
	}
	return v, nil
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type row struct {
	View
	tenantID, resourcePK, resourceSHA string
	configSHA                         string // "" for remediations proposed before it was recorded
	signed                            *signing.Signed
}

const viewCols = `id, tenant_id, source, rule_id, resource_pk, resource_id, account_id, operations, justification, requested_by,
	status, required_approvals, disruptive, simulation, plan_sha256, resource_version, resource_sha256, policy_bundle_sha,
	created_at, released_at, coalesce(released_by, ''), verified_at, verification, stale_reason, change_set_signed,
	coalesce(policy_config_sha256, ''), coalesce(pull_request_url, '')`

func scanRow(r pgx.Row) (row, error) {
	var x row
	var ops, sim, ver []byte
	var signedText *string
	err := r.Scan(&x.ID, &x.tenantID, &x.Source, &x.RuleID, &x.resourcePK, &x.ResourceID, &x.AccountID, &ops, &x.Justification,
		&x.RequestedBy, &x.Status, &x.RequiredApprovals, &x.Disruptive, &sim, &x.PlanSHA256, &x.ResourceVersion, &x.resourceSHA,
		&x.PolicyBundleSHA, &x.CreatedAt, &x.ReleasedAt, &x.ReleasedBy, &x.VerifiedAt, &ver, &x.StaleReason, &signedText, &x.configSHA, &x.PullRequestURL)
	if errors.Is(err, pgx.ErrNoRows) {
		return row{}, ErrNotFound
	}
	if err != nil {
		return row{}, err
	}
	if len(ver) > 0 {
		x.Verification = ver
	}
	if signedText != nil {
		var sig signing.Signed
		if err := json.Unmarshal([]byte(*signedText), &sig); err != nil {
			return row{}, err
		}
		x.signed = &sig
	}
	return x, errors.Join(json.Unmarshal(ops, &x.Operations), json.Unmarshal(sim, &x.Simulation))
}

func (s *Service) approvals(ctx context.Context, q querier, id string) ([]Approval, error) {
	rows, err := q.Query(ctx, `SELECT actor, decision, plan_sha256, comment, created_at FROM remediation_approvals
		WHERE remediation_id = $1 ORDER BY created_at, actor`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Approval{}
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.Actor, &a.Decision, &a.PlanSHA256, &a.Comment, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (x row) changeSet(nativeType string) *ChangeSet {
	return &ChangeSet{PlanSHA256: x.PlanSHA256, ResourceID: x.ResourceID, AccountID: x.AccountID, NativeType: nativeType,
		Operations: x.Operations, Diff: x.Simulation.Diff, Instructions: releaseInstructions, Signed: x.signed}
}

// Get returns one remediation with its approvals (and change set once released).
func (s *Service) Get(ctx context.Context, tenant, id string) (View, error) {
	if !uuidRe.MatchString(id) {
		return View{}, ErrNotFound
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return View{}, err
	}
	x, err := scanRow(s.Pool.QueryRow(ctx, `SELECT `+viewCols+` FROM remediations WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if err != nil {
		return View{}, err
	}
	if x.Approvals, err = s.approvals(ctx, s.Pool, id); err != nil {
		return View{}, err
	}
	var upd time.Time
	if err := s.Pool.QueryRow(ctx, `SELECT current_version, updated_at FROM resources WHERE id = $1`, x.resourcePK).Scan(&x.ObservedVersion, &upd); err == nil {
		x.ObservedUpdatedAt = &upd
	}
	if x.ReleasedAt != nil {
		var native string
		_ = s.Pool.QueryRow(ctx, `SELECT native_type FROM resources WHERE id = $1`, x.resourcePK).Scan(&native)
		x.ChangeSet = x.changeSet(native)
	}
	return x.View, nil
}

// List returns one page of the tenant's remediations, newest first,
// optionally by status, and the cursor of the next page ("" at the end).
func (s *Service) List(ctx context.Context, tenant, status, after string, limit int) ([]View, string, error) {
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return nil, "", err
	}
	at, id, hasCursor, err := paging.Decode(after)
	if err != nil || (hasCursor && !uuidRe.MatchString(id)) {
		return nil, "", fmt.Errorf("%w: invalid cursor", ErrInvalid)
	}
	limit = paging.Limit(limit)
	rows, err := s.Pool.Query(ctx, `SELECT `+viewCols+` FROM remediations WHERE tenant_id = $1 AND ($2 = '' OR status = $2)
		AND (NOT $3 OR (created_at, id) < ($4, $5::uuid))
		ORDER BY created_at DESC, id DESC LIMIT $6`, tenantID, status, hasCursor, at, nullUUID(id), limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []View{}
	for rows.Next() {
		x, err := scanRow(rows)
		if err != nil {
			return nil, "", err
		}
		x.Approvals = []Approval{} // details are on GET /remediations/{id}
		out = append(out, x.View)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = paging.Encode(last.CreatedAt, last.ID)
	}
	return out, next, nil
}

func nullUUID(id string) string {
	if id == "" {
		return "00000000-0000-0000-0000-000000000000"
	}
	return id
}

// withLocked runs fn on the locked remediation row in one transaction. If
// fn returns a *committing error, its writes are committed before the
// error is returned (used to record denials and staleness).
type committing struct{ err error }

func (c *committing) Error() string { return c.err.Error() }
func (c *committing) Unwrap() error { return c.err }

func (s *Service) withLocked(ctx context.Context, tenant, id string, fn func(tx pgx.Tx, x *row) error) (View, error) {
	if !uuidRe.MatchString(id) {
		return View{}, ErrNotFound
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return View{}, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return View{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	x, err := scanRow(tx.QueryRow(ctx, `SELECT `+viewCols+` FROM remediations WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, id))
	if err != nil {
		return View{}, err
	}
	if ferr := fn(tx, &x); ferr != nil {
		var c *committing
		if errors.As(ferr, &c) {
			if err := tx.Commit(ctx); err != nil {
				return View{}, err
			}
			return View{}, c.err
		}
		return View{}, ferr
	}
	if x.Approvals, err = s.approvals(ctx, tx, id); err != nil {
		return View{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return View{}, err
	}
	return x.View, nil
}

// checkFresh marks the remediation stale if the resource changed since simulation.
// checkFresh marks the remediation stale if the resource or the policies
// changed since it was simulated. The resource row stays share-locked until
// the transaction ends, so it cannot change before the decision commits.
//
// The policy bundle is fetched by the caller before the row lock is taken
// (policyBundle), so no OPA call happens while the remediation is locked.
func (s *Service) checkFresh(ctx context.Context, tx pgx.Tx, x *row, actor string, b bundleCheck) (resource, error) {
	cur, err := loadByPKLock(ctx, tx, x.tenantID, x.resourcePK, "FOR SHARE OF r")
	if err != nil {
		return resource{}, err
	}
	reason := ""
	switch {
	case cur.deleted:
		reason = "the resource was deleted"
	case cur.version != x.ResourceVersion || cur.sha != x.resourceSHA:
		reason = fmt.Sprintf("the resource changed (version %d, simulated against %d)", cur.version, x.ResourceVersion)
	default:
		if b.err != nil {
			return resource{}, fmt.Errorf("policy bundle: %w", b.err)
		}
		if b.sha != x.PolicyBundleSHA {
			reason = "the policies changed since the simulation"
			break
		}
		if x.configSHA != "" {
			pcfg, err := tenancy.Load(ctx, tx, x.tenantID)
			if err != nil {
				return resource{}, fmt.Errorf("policy configuration: %w", err)
			}
			if pcfg.SHA256() != x.configSHA {
				reason = "the tenant policy configuration changed since the simulation"
			}
		}
	}
	if reason == "" {
		return cur, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE remediations SET status = 'stale', stale_reason = $2 WHERE id = $1`, x.ID, reason); err != nil {
		return resource{}, err
	}
	if err := audit.Append(ctx, tx, x.tenantID, audit.Event{Actor: actor, Action: "remediation.stale", TargetType: "remediation",
		TargetID: x.ID, Outcome: "failure", Details: map[string]any{"reason": reason, "pinned_version": x.ResourceVersion,
			"current_version": cur.version}}); err != nil {
		return resource{}, err
	}
	return resource{}, &committing{fmt.Errorf("%w (%s)", ErrStale, reason)}
}

// bundleCheck is the policy bundle hash fetched before a row lock is taken;
// an OPA error is kept and reported only if the hash is needed.
type bundleCheck struct {
	sha string
	err error
}

func (s *Service) policyBundle(ctx context.Context) bundleCheck {
	b, err := s.OPA.Bundle(ctx)
	return bundleCheck{sha: b.SHA256, err: err}
}

// Decide records an approval or rejection. The requester cannot decide their
// own remediation, nobody decides twice, and a stale plan cannot be approved.
func (s *Service) Decide(ctx context.Context, tenant, actor, id, decision, comment string) (View, error) {
	if decision != "approve" && decision != "reject" {
		return View{}, fmt.Errorf("%w: decision must be approve or reject", ErrInvalid)
	}
	if len([]rune(comment)) > 1000 {
		return View{}, fmt.Errorf("%w: comment must be at most 1000 characters", ErrInvalid)
	}
	b := s.policyBundle(ctx)
	return s.withLocked(ctx, tenant, id, func(tx pgx.Tx, x *row) error {
		if x.Status != StatusPending {
			return fmt.Errorf("%w: remediation is %s, not pending_approval", ErrConflict, x.Status)
		}
		if actor == x.RequestedBy {
			if err := audit.Append(ctx, tx, x.tenantID, audit.Event{Actor: actor, Action: "remediation." + decision, TargetType: "remediation",
				TargetID: x.ID, Outcome: "denied", Details: map[string]any{"reason": "requester cannot decide their own remediation"}}); err != nil {
				return err
			}
			return &committing{fmt.Errorf("%w: the requester cannot approve or reject their own remediation", ErrForbidden)}
		}
		if _, err := s.checkFresh(ctx, tx, x, actor, b); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO remediation_approvals (remediation_id, actor, decision, plan_sha256, comment)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, x.ID, actor, decision, x.PlanSHA256, comment)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s has already decided this remediation", ErrConflict, actor)
		}
		if decision == "reject" {
			x.Status = StatusRejected
		} else {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM remediation_approvals WHERE remediation_id = $1 AND decision = 'approve'
				AND plan_sha256 = $2`, x.ID, x.PlanSHA256).Scan(&n); err != nil {
				return err
			}
			if n >= x.RequiredApprovals {
				x.Status = StatusApproved
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE remediations SET status = $2 WHERE id = $1`, x.ID, x.Status); err != nil {
			return err
		}
		return audit.Append(ctx, tx, x.tenantID, audit.Event{Actor: actor, Action: "remediation." + decision, TargetType: "remediation",
			TargetID: x.ID, Outcome: "success", Details: map[string]any{"plan_sha256": x.PlanSHA256, "status": x.Status}})
	})
}

// Release hands an approved remediation to the change pipeline as a change
// set. It changes nothing in the cloud.
func (s *Service) Release(ctx context.Context, tenant, actor, id string) (View, error) {
	var native string
	b := s.policyBundle(ctx)
	v, err := s.withLocked(ctx, tenant, id, func(tx pgx.Tx, x *row) error {
		if x.Status != StatusApproved {
			return fmt.Errorf("%w: remediation is %s; only approved remediations can be released", ErrConflict, x.Status)
		}
		cur, err := s.checkFresh(ctx, tx, x, actor, b)
		if err != nil {
			return err
		}
		native = cur.nativeType
		now := s.now().UTC()
		x.Status, x.ReleasedAt, x.ReleasedBy = StatusReleased, &now, actor
		var signedJSON any // NULL when unsigned
		if s.Signer != nil {
			approvals, err := s.approvals(ctx, tx, x.ID)
			if err != nil {
				return err
			}
			approvers := []string{}
			for _, a := range approvals {
				if a.Decision == "approve" {
					approvers = append(approvers, a.Actor)
				}
			}
			sig, err := s.Signer.Sign(signedChangeSet{Type: "aegis.changeset/v1", RemediationID: x.ID, PlanSHA256: x.PlanSHA256,
				RuleID: x.RuleID, ResourceID: x.ResourceID, AccountID: x.AccountID, NativeType: native, Operations: x.Operations,
				RequestedBy: x.RequestedBy, ApprovedBy: approvers, ReleasedBy: actor, ReleasedAt: now.Format(time.RFC3339)})
			if err != nil {
				return err
			}
			x.signed = &sig
			raw, _ := json.Marshal(sig)
			signedJSON = string(raw)
		}
		if _, err := tx.Exec(ctx, `UPDATE remediations SET status = 'released', released_at = $2, released_by = $3,
			change_set_signed = $4 WHERE id = $1`, x.ID, now, actor, signedJSON); err != nil {
			return err
		}
		x.ChangeSet = x.changeSet(native)
		return audit.Append(ctx, tx, x.tenantID, audit.Event{Actor: actor, Action: "remediation.released", TargetType: "remediation",
			TargetID: x.ID, Outcome: "success", Details: map[string]any{"plan_sha256": x.PlanSHA256, "executor": "export-only"}})
	})
	return v, err
}

// Verification records what the observed inventory shows after release.
type Verification struct {
	ObservedVersion  int      `json:"observed_version"`
	ConfigMatches    bool     `json:"config_matches"`
	Mismatched       []string `json:"mismatched_paths"`
	FailingNow       []string `json:"failing_now"`
	TargetResolved   bool     `json:"target_resolved"`
	UnexpectedFailed []string `json:"unexpected_failures"`
	Verified         bool     `json:"verified"`
}

// Verify compares the current inventory with the released plan: the approved
// values must be present, the target rule must pass, and no rule may fail
// that the simulation did not predict.
func (s *Service) Verify(ctx context.Context, tenant, actor, id string) (View, error) {
	return s.withLocked(ctx, tenant, id, func(tx pgx.Tx, x *row) error {
		if x.Status != StatusReleased && x.Status != StatusVerificationFailed {
			return fmt.Errorf("%w: remediation is %s; only released remediations can be verified", ErrConflict, x.Status)
		}
		cur, err := loadByPK(ctx, tx, x.tenantID, x.resourcePK)
		if err != nil {
			return err
		}
		if !cur.deleted && cur.version == x.ResourceVersion {
			return ErrNotObserved
		}
		ver := Verification{ObservedVersion: cur.version, Mismatched: []string{}, FailingNow: []string{}, UnexpectedFailed: []string{}}
		if !cur.deleted {
			ver.ConfigMatches, ver.Mismatched = Matches(cur.state, x.Operations)
			if ver.Mismatched == nil {
				ver.Mismatched = []string{}
			}
			pcfg, err := tenancy.Load(ctx, tx, x.tenantID)
			if err != nil {
				return err
			}
			if ver.FailingNow, err = s.failing(ctx, cur.state, pcfg.Input()); err != nil {
				return err
			}
			ver.TargetResolved = x.RuleID == "" || !slices.Contains(ver.FailingNow, x.RuleID)
			ver.UnexpectedFailed = minus(ver.FailingNow, x.Simulation.After)
		}
		ver.Verified = !cur.deleted && ver.ConfigMatches && ver.TargetResolved && len(ver.UnexpectedFailed) == 0
		x.Status = StatusVerificationFailed
		outcome := "failure"
		if ver.Verified {
			x.Status, outcome = StatusVerified, "success"
		}
		now := s.now().UTC()
		raw, _ := json.Marshal(ver)
		x.VerifiedAt, x.Verification = &now, raw
		if _, err := tx.Exec(ctx, `UPDATE remediations SET status = $2, verified_at = $3, verification = $4 WHERE id = $1`,
			x.ID, x.Status, now, raw); err != nil {
			return err
		}
		return audit.Append(ctx, tx, x.tenantID, audit.Event{Actor: actor, Action: "remediation.verified", TargetType: "remediation",
			TargetID: x.ID, Outcome: outcome, Details: map[string]any{"verified": ver.Verified, "observed_version": cur.version}})
	})
}
