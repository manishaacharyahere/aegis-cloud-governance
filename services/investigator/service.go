package investigator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
)

// Model statuses.
const (
	StatusNotConfigured = "not_configured"
	StatusAccepted      = "accepted"
	StatusPartial       = "partially_accepted"
	StatusRejected      = "rejected"
	StatusError         = "error"
)

// Notice is returned with every investigation.
const Notice = "Generated from Aegis records only. The assistant cannot change, approve or execute anything; " +
	"policy results come from deterministic rules and decisions from human approvers. " +
	"Model claims are checked against the cited evidence for facts, not meaning: treat them as a draft and rely on the brief."

// Service is Module G.
type Service struct {
	Pool  *pgxpool.Pool
	Rules map[string]RuleMeta
	Model Model // nil: deterministic briefs only
	// ModelTimeout bounds one model call (default 60s).
	ModelTimeout time.Duration
	Now          func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Request starts an investigation of one inventory resource.
type Request struct {
	ResourceID string `json:"resource_id"`
	AccountID  string `json:"account_id"` // provider account ID; needed only if resource_id is in several accounts
	Question   string `json:"question"`
}

// ModelResult records what the optional model said and what survived validation.
type ModelResult struct {
	Status        string      `json:"status"`
	Model         string      `json:"model,omitempty"`
	PromptVersion string      `json:"prompt_version,omitempty"`
	Accepted      []Claim     `json:"accepted"`
	Rejected      []Rejection `json:"rejected"`
	Error         string      `json:"error,omitempty"`
	LatencyMS     int64       `json:"latency_ms,omitempty"`
}

// Investigation is a stored investigation.
type Investigation struct {
	ID             string      `json:"id"`
	Subject        string      `json:"resource_id"`
	Account        string      `json:"account_id"`
	Question       string      `json:"question"`
	Actor          string      `json:"actor"`
	CreatedAt      time.Time   `json:"created_at"`
	EvidenceSHA256 string      `json:"evidence_sha256"`
	Evidence       []Evidence  `json:"evidence"`
	Brief          Brief       `json:"brief"`
	Model          ModelResult `json:"model"`
	Notice         string      `json:"notice"`
}

// Status reports whether a model is configured.
func (s *Service) Status() map[string]any {
	st := map[string]any{"mode": "deterministic", "model": nil, "prompt_version": PromptVersion,
		"note": "Investigations always return a deterministic, cited brief; a model only adds validated explanations."}
	if s.Model != nil {
		st["mode"] = "deterministic+model"
		st["model"] = s.Model.Name()
	}
	return st
}

var accountRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

// cleanQuestion drops control characters (log and prompt hygiene) and caps length.
func cleanQuestion(q string) (string, error) {
	q = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(q))
	if len([]rune(q)) > 1000 {
		return "", fmt.Errorf("%w: question must be at most 1000 characters", ErrInvalid)
	}
	return q, nil
}

func (s *Service) tenantID(ctx context.Context, slug string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, slug).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTenantNotFound
	}
	return id, err
}

// Investigate collects evidence, writes the deterministic brief, optionally
// asks the model, validates its claims and stores everything.
func (s *Service) Investigate(ctx context.Context, tenant, actor string, req Request) (Investigation, error) {
	req.ResourceID = strings.TrimSpace(req.ResourceID)
	if n := len(req.ResourceID); n == 0 || n > 512 {
		return Investigation{}, fmt.Errorf("%w: resource_id must be 1-512 characters", ErrInvalid)
	}
	if req.AccountID != "" && !accountRe.MatchString(req.AccountID) {
		return Investigation{}, fmt.Errorf("%w: invalid account_id", ErrInvalid)
	}
	q, err := cleanQuestion(req.Question)
	if err != nil {
		return Investigation{}, err
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return Investigation{}, err
	}

	// Evidence is read in one read-only, repeatable-read transaction: a
	// consistent snapshot, and the database itself refuses any write.
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return Investigation{}, err
	}
	bundle, err := collect(ctx, tx, tenantID, req.ResourceID, req.AccountID, s.Rules, s.now())
	_ = tx.Rollback(ctx)
	if err != nil {
		return Investigation{}, err
	}

	inv := Investigation{
		Subject: bundle.Subject, Account: bundle.Account, Question: q, Actor: actor,
		EvidenceSHA256: bundle.SHA256(), Evidence: bundle.Items, Brief: MakeBrief(bundle), Notice: Notice,
		Model: ModelResult{Status: StatusNotConfigured, Accepted: []Claim{}, Rejected: []Rejection{}},
	}
	var raw string
	if s.Model != nil {
		inv.Model, raw = s.ask(ctx, q, bundle)
	}

	evidenceJSON, _ := json.Marshal(inv.Evidence)
	briefJSON, _ := json.Marshal(inv.Brief)
	modelJSON, _ := json.Marshal(inv.Model)
	if len(raw) > 16384 {
		raw = strings.ToValidUTF8(raw[:16384], "") // never split a rune
	}
	raw = strings.ReplaceAll(raw, "\x00", "") // PostgreSQL text cannot hold NUL
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO investigations
			(tenant_id, resource_id, account_id, question, actor, evidence, evidence_sha256, brief, model_status, model, model_raw)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id, created_at`,
			tenantID, inv.Subject, inv.Account, q, actor, evidenceJSON, inv.EvidenceSHA256, briefJSON,
			inv.Model.Status, modelJSON, raw).Scan(&inv.ID, &inv.CreatedAt); err != nil {
			return err
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{
			Actor: actor, Action: "investigation.created", TargetType: "investigation", TargetID: inv.ID, Outcome: "success",
			Details: map[string]any{"resource_id": inv.Subject, "evidence_items": len(inv.Evidence),
				"evidence_sha256": inv.EvidenceSHA256, "model_status": inv.Model.Status,
				"model_claims_accepted": len(inv.Model.Accepted), "model_claims_rejected": len(inv.Model.Rejected)},
		})
	})
	if err != nil {
		return Investigation{}, err
	}
	return inv, nil
}

// ask calls the model and validates its claims. Model failures never fail
// the investigation: the deterministic brief is already complete.
func (s *Service) ask(ctx context.Context, question string, b Bundle) (ModelResult, string) {
	res := ModelResult{Model: s.Model.Name(), PromptVersion: PromptVersion, Accepted: []Claim{}, Rejected: []Rejection{}}
	timeout := s.ModelTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	mctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if question == "" {
		question = "Explain the most important findings about this resource and why they matter."
	}
	system, user := BuildPrompt(question, b)
	start := time.Now()
	raw, err := s.Model.Generate(mctx, system, user)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Status, res.Error = StatusError, "model call failed"
		if errors.Is(err, context.DeadlineExceeded) {
			res.Error = "model call timed out"
		}
		return res, ""
	}
	claims, err := ParseClaims(raw)
	if err != nil {
		res.Status, res.Error = StatusError, "model output was not the required JSON"
		return res, raw
	}
	acc, rej := Validate(b, claims)
	if acc != nil {
		res.Accepted = acc
	}
	if rej != nil {
		res.Rejected = rej
	}
	switch {
	case len(acc) > 0 && len(rej) == 0:
		res.Status = StatusAccepted
	case len(acc) > 0:
		res.Status = StatusPartial
	default:
		res.Status = StatusRejected
	}
	return res, raw
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Get returns a stored investigation.
func (s *Service) Get(ctx context.Context, tenant, id string) (Investigation, error) {
	if !uuidRe.MatchString(id) {
		return Investigation{}, ErrNotFound
	}
	tenantID, err := s.tenantID(ctx, tenant)
	if err != nil {
		return Investigation{}, err
	}
	inv := Investigation{ID: id, Notice: Notice}
	var ev, br, mo []byte
	err = s.Pool.QueryRow(ctx, `SELECT resource_id, account_id, question, actor, created_at, evidence_sha256, evidence, brief, model
		FROM investigations WHERE tenant_id = $1 AND id = $2`, tenantID, id).
		Scan(&inv.Subject, &inv.Account, &inv.Question, &inv.Actor, &inv.CreatedAt, &inv.EvidenceSHA256, &ev, &br, &mo)
	if errors.Is(err, pgx.ErrNoRows) {
		return Investigation{}, ErrNotFound
	}
	if err != nil {
		return Investigation{}, err
	}
	if err := errors.Join(json.Unmarshal(ev, &inv.Evidence), json.Unmarshal(br, &inv.Brief), json.Unmarshal(mo, &inv.Model)); err != nil {
		return Investigation{}, err
	}
	return inv, nil
}
