package iac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/paging"
)

// Scan statuses.
const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
)

// Store errors.
var (
	ErrTenantNotFound = errors.New("tenant not found")
	ErrNotFound       = errors.New("not found")
	ErrLeaseLost      = errors.New("scan lease lost to another worker")
	// ErrIdempotencyConflict: the idempotency key was used for another request.
	ErrIdempotencyConflict = errors.New("idempotency key already used for a different request")
	ErrInvalidCursor       = errors.New("invalid cursor")
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Scan is the API view of a scan.
type Scan struct {
	ID                 string            `json:"id"`
	SourceType         string            `json:"source_type"`
	SourceRef          string            `json:"source_ref"`
	Status             string            `json:"status"`
	Attempts           int               `json:"attempts"`
	MaxAttempts        int               `json:"max_attempts"`
	LastError          string            `json:"last_error,omitempty"`
	ErrorClass         string            `json:"error_class,omitempty"`
	ToolVersions       map[string]string `json:"tool_versions"`
	PolicyBundleSHA256 string            `json:"policy_bundle_sha256,omitempty"`
	PlanSummary        *Summary          `json:"plan_summary,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	StartedAt          *time.Time        `json:"started_at,omitempty"`
	FinishedAt         *time.Time        `json:"finished_at,omitempty"`
}

// ChangeView is a stored planned change.
type ChangeView struct {
	Address      string `json:"address"`
	ResourceType string `json:"resource_type"`
	Action       string `json:"action"`
	Destructive  bool   `json:"destructive"`
	Region       string `json:"region,omitempty"`
}

// Report is a scan with its planned changes, findings and roll-ups.
type Report struct {
	Scan
	Changes  []ChangeView              `json:"planned_changes"`
	Findings []Finding                 `json:"findings"`
	Counts   map[string]map[string]int `json:"counts"`   // source -> severity -> n
	Blocking int                       `json:"blocking"` // policy deny findings
}

// Job is a claimed unit of work.
type Job struct {
	ScanID      string
	TenantID    string
	SourceType  string
	SourceRef   string
	Attempt     int
	MaxAttempts int
}

// Store persists scans in PostgreSQL.
type Store struct{ pool *pgxpool.Pool }

// NewStore returns a Store.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Enqueue creates a queued scan for actor. With an idempotency key, repeating
// the same request (same actor and fixture) returns the existing scan
// (created=false); reusing the key for a different request is
// ErrIdempotencyConflict.
func (s *Store) Enqueue(ctx context.Context, tenantSlug, actor, fixture, idemKey string) (scan Scan, created bool, err error) {
	var tenantID string
	if err := s.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, tenantSlug).Scan(&tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Scan{}, false, ErrTenantNotFound
		}
		return Scan{}, false, err
	}
	var key any
	if idemKey != "" {
		key = idemKey
	}
	var id string
	err = s.pool.QueryRow(ctx, `
		INSERT INTO iac_scans (tenant_id, source_type, source_ref, idempotency_key, requested_by)
		VALUES ($1, 'fixture', $2, $3, $4)
		ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
		RETURNING id`, tenantID, fixture, key, actor).Scan(&id)
	switch {
	case err == nil:
		created = true
	case errors.Is(err, pgx.ErrNoRows): // idempotent replay
		var ref string
		var by *string
		if err := s.pool.QueryRow(ctx, `SELECT id, source_ref, requested_by FROM iac_scans WHERE tenant_id = $1 AND idempotency_key = $2`,
			tenantID, idemKey).Scan(&id, &ref, &by); err != nil {
			return Scan{}, false, err
		}
		// Another caller's key, or the same key for a different fixture: never
		// hand back a scan that answers a different request.
		if ref != fixture || by == nil || *by != actor {
			return Scan{}, false, ErrIdempotencyConflict
		}
	default:
		return Scan{}, false, fmt.Errorf("enqueue scan: %w", err)
	}
	scan, err = s.get(ctx, tenantID, id)
	return scan, created, err
}

// Claim atomically leases the next runnable scan: a queued scan whose
// backoff has elapsed, or a running scan whose lease expired (its worker
// crashed). Returns (nil, nil) when there is no work.
func (s *Store) Claim(ctx context.Context, owner string, lease time.Duration) (*Job, error) {
	var j Job
	err := s.pool.QueryRow(ctx, `
		UPDATE iac_scans SET status = 'running', attempts = attempts + 1, lease_owner = $1,
			lease_expires_at = now() + $2 * interval '1 millisecond', started_at = coalesce(started_at, now())
		WHERE id = (
			SELECT id FROM iac_scans
			WHERE (status = 'queued' AND next_attempt_at <= now())
			   OR (status = 'running' AND lease_expires_at < now())
			ORDER BY next_attempt_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1)
		RETURNING id, tenant_id, source_type, source_ref, attempts, max_attempts`,
		owner, lease.Milliseconds()).Scan(&j.ScanID, &j.TenantID, &j.SourceType, &j.SourceRef, &j.Attempt, &j.MaxAttempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim scan: %w", err)
	}
	return &j, nil
}

// Renew extends the lease while the job is still owned by owner.
func (s *Store) Renew(ctx context.Context, j *Job, owner string, lease time.Duration) error {
	tag, err := s.pool.Exec(ctx, `UPDATE iac_scans SET lease_expires_at = now() + $3 * interval '1 millisecond'
		WHERE id = $1 AND lease_owner = $2 AND status = 'running'`, j.ScanID, owner, lease.Milliseconds())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLeaseLost
	}
	return nil
}

// Complete stores results and marks the scan succeeded in one transaction.
// It is idempotent (previous partial results for the scan are replaced) and
// refuses to write if the lease was lost.
func (s *Store) Complete(ctx context.Context, j *Job, owner string, r Result) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		summary, _ := json.Marshal(r.Analysis.Summary)
		versions, _ := json.Marshal(r.ToolVersions)
		tag, err := tx.Exec(ctx, `
			UPDATE iac_scans SET status = 'succeeded', finished_at = now(), lease_owner = NULL, lease_expires_at = NULL,
				last_error = NULL, error_class = NULL, plan_summary = $3, tool_versions = $4, policy_bundle_sha256 = $5
			WHERE id = $1 AND lease_owner = $2 AND status = 'running'`,
			j.ScanID, owner, summary, versions, r.PolicyBundleSHA256)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrLeaseLost
		}
		if r.PolicyBundle.SHA256 != "" && len(r.PolicyBundle.Modules) > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO policy_bundles (sha256, modules) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
				r.PolicyBundle.SHA256, mustJSON(r.PolicyBundle.Modules)); err != nil {
				return fmt.Errorf("record policy bundle: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM iac_planned_changes WHERE scan_id = $1`, j.ScanID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM iac_findings WHERE scan_id = $1`, j.ScanID); err != nil {
			return err
		}
		changes := make([][]any, 0, len(r.Analysis.Resources))
		for _, pr := range r.Analysis.Resources {
			detail, _ := json.Marshal(pr)
			changes = append(changes, []any{j.ScanID, pr.Address, pr.Type, string(pr.Action), pr.Destructive, pr.Region, detail})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"iac_planned_changes"},
			[]string{"scan_id", "address", "resource_type", "action", "destructive", "region", "detail"},
			pgx.CopyFromRows(changes)); err != nil {
			return fmt.Errorf("store planned changes: %w", err)
		}
		rows := make([][]any, 0, len(r.Findings))
		for _, f := range r.Findings {
			rows = append(rows, []any{j.ScanID, j.TenantID, f.Source, f.RuleID, f.Severity, f.Decision,
				f.ResourceAddress, f.FilePath, f.StartLine, f.EndLine, f.Title, f.Fingerprint})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"iac_findings"},
			[]string{"scan_id", "tenant_id", "source", "rule_id", "severity", "decision", "resource_address",
				"file_path", "start_line", "end_line", "title", "fingerprint"},
			pgx.CopyFromRows(rows)); err != nil {
			return fmt.Errorf("store findings: %w", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO outbox_events (tenant_id, aggregate_type, aggregate_id, event_type, payload)
			VALUES ($1, 'iac_scan', $2, 'iac.scan.succeeded', $3)`, j.TenantID, j.ScanID,
			mustJSON(map[string]any{"scan_id": j.ScanID, "findings": len(r.Findings), "summary": r.Analysis.Summary}))
		return err
	})
}

// Fail records a failure. Retryable failures with attempts left are
// re-queued with exponential backoff and full jitter; others are final.
func (s *Store) Fail(ctx context.Context, j *Job, owner string, cause error, base, maxDelay time.Duration) (final bool, err error) {
	retry := IsRetryable(cause) && j.Attempt < j.MaxAttempts
	class := "permanent"
	if IsRetryable(cause) {
		class = "retryable"
	}
	msg := cause.Error()
	if len(msg) > 2000 {
		msg = strings.ToValidUTF8(msg[:2000], "") // a cut rune would make PostgreSQL reject the update
	}
	var tag pgconn.CommandTag
	if retry {
		delay := Backoff(j.Attempt, base, maxDelay)
		tag, err = s.pool.Exec(ctx, `
			UPDATE iac_scans SET status = 'queued', next_attempt_at = now() + $3 * interval '1 millisecond',
				lease_owner = NULL, lease_expires_at = NULL, last_error = $4, error_class = $5
			WHERE id = $1 AND lease_owner = $2 AND status = 'running'`, j.ScanID, owner, delay.Milliseconds(), msg, class)
	} else {
		tag, err = s.pool.Exec(ctx, `
			UPDATE iac_scans SET status = 'failed', finished_at = now(), lease_owner = NULL, lease_expires_at = NULL,
				last_error = $3, error_class = $4
			WHERE id = $1 AND lease_owner = $2 AND status = 'running'`, j.ScanID, owner, msg, class)
	}
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, ErrLeaseLost
	}
	return !retry, nil
}

// Backoff returns a full-jitter exponential delay for the given attempt
// (1-based): uniform in [0, min(max, base*2^(attempt-1))].
func Backoff(attempt int, base, maxDelay time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	ceiling := base
	for i := 1; i < attempt && ceiling < maxDelay; i++ {
		ceiling *= 2
	}
	if ceiling > maxDelay {
		ceiling = maxDelay
	}
	if ceiling <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(ceiling) + 1))
}

// Get returns a scan's full report, tenant-scoped.
func (s *Store) Get(ctx context.Context, tenantSlug, id string) (Report, error) {
	if !uuidRe.MatchString(id) {
		return Report{}, ErrNotFound
	}
	var tenantID string
	if err := s.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, tenantSlug).Scan(&tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Report{}, ErrTenantNotFound
		}
		return Report{}, err
	}
	scan, err := s.get(ctx, tenantID, id)
	if err != nil {
		return Report{}, err
	}
	rep := Report{Scan: scan, Changes: []ChangeView{}, Findings: []Finding{}, Counts: map[string]map[string]int{}}

	rows, err := s.pool.Query(ctx, `SELECT address, resource_type, action, destructive, region
		FROM iac_planned_changes WHERE scan_id = $1 ORDER BY address`, id)
	if err != nil {
		return Report{}, err
	}
	if rep.Changes, err = pgx.CollectRows(rows, pgx.RowToStructByPos[ChangeView]); err != nil {
		return Report{}, err
	}

	rows, err = s.pool.Query(ctx, `SELECT source, rule_id, severity, decision, resource_address, file_path,
		start_line, end_line, title, fingerprint FROM iac_findings WHERE scan_id = $1`, id)
	if err != nil {
		return Report{}, err
	}
	fs, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Finding])
	if err != nil {
		return Report{}, err
	}
	rep.Findings = Merge(fs) // re-sort consistently
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	for _, f := range rep.Findings {
		if rep.Counts[f.Source] == nil {
			rep.Counts[f.Source] = map[string]int{}
		}
		rep.Counts[f.Source][f.Severity]++
		if f.Decision == "deny" {
			rep.Blocking++
		}
	}
	return rep, nil
}

const scanCols = `id, source_type, source_ref, status, attempts, max_attempts, last_error, error_class,
	tool_versions, policy_bundle_sha256, plan_summary, created_at, started_at, finished_at`

func scanRow(row pgx.Row) (Scan, error) {
	var sc Scan
	var versions, summary []byte
	var lastErr, class, bundle *string
	if err := row.Scan(&sc.ID, &sc.SourceType, &sc.SourceRef, &sc.Status, &sc.Attempts, &sc.MaxAttempts, &lastErr, &class,
		&versions, &bundle, &summary, &sc.CreatedAt, &sc.StartedAt, &sc.FinishedAt); err != nil {
		return Scan{}, err
	}
	sc.LastError, sc.ErrorClass, sc.PolicyBundleSHA256 = deref(lastErr), deref(class), deref(bundle)
	_ = json.Unmarshal(versions, &sc.ToolVersions)
	if len(summary) > 0 {
		sc.PlanSummary = &Summary{}
		_ = json.Unmarshal(summary, sc.PlanSummary)
	}
	return sc, nil
}

func (s *Store) get(ctx context.Context, tenantID, id string) (Scan, error) {
	sc, err := scanRow(s.pool.QueryRow(ctx, `SELECT `+scanCols+` FROM iac_scans WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Scan{}, ErrNotFound
	}
	if err != nil {
		return Scan{}, fmt.Errorf("get scan: %w", err)
	}
	return sc, nil
}

// List returns a tenant's scans newest first (without findings), with an
// opaque cursor for the next page ("" when there is none).
func (s *Store) List(ctx context.Context, tenantSlug, after string, limit int) ([]Scan, string, error) {
	at, id, hasCursor, err := paging.Decode(after)
	if err != nil || (hasCursor && !uuidRe.MatchString(id)) {
		return nil, "", ErrInvalidCursor
	}
	var tenantID string
	if err := s.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, tenantSlug).Scan(&tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", ErrTenantNotFound
		}
		return nil, "", err
	}
	if !hasCursor {
		id = "00000000-0000-0000-0000-000000000000"
	}
	limit = paging.Limit(limit)
	rows, err := s.pool.Query(ctx, `SELECT `+scanCols+` FROM iac_scans WHERE tenant_id = $1
		AND (NOT $2 OR (created_at, id) < ($3, $4::uuid)) ORDER BY created_at DESC, id DESC LIMIT $5`,
		tenantID, hasCursor, at, id, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []Scan{}
	for rows.Next() {
		sc, err := scanRow(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = paging.Encode(out[limit-1].CreatedAt, out[limit-1].ID)
	}
	return out, next, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
