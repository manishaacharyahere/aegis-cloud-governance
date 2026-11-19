package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/paging"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/signing"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/access"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
)

// ComplianceService is the subset of the compliance module used by the API.
type ComplianceService interface {
	EvaluateInventory(ctx context.Context, tenant, actor string) (compliance.RunSummary, error)
	EvaluateScan(ctx context.Context, tenant, scanID, actor string) (compliance.RunSummary, error)
	Coverage(ctx context.Context, tenant, framework, scope string, staleAfter time.Duration) (compliance.Coverage, error)
	Control(ctx context.Context, tenant, framework, control, scope string, staleAfter time.Duration) (compliance.ControlDetail, error)
	RequestException(ctx context.Context, tenant, actor string, req compliance.ExceptionRequest) (compliance.ExceptionView, error)
	DecideException(ctx context.Context, tenant, actor, id, decision string) (compliance.ExceptionView, error)
	ListExceptions(ctx context.Context, tenant, after string, limit int) ([]compliance.ExceptionView, string, error)
	AuditEvents(ctx context.Context, tenant string, limit int, beforeSeq int64) ([]audit.Record, error)
	VerifyAudit(ctx context.Context, tenant string) (audit.Verification, error)
	AuditHashAt(ctx context.Context, tenant string, seq int64) (string, error)
}

// ActorHeader identifies who performs an action in development header mode
// only; with OIDC the actor is the verified token subject (docs/auth.md).
const ActorHeader = "X-Aegis-Actor"

var actorRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{0,63}$`)

type complianceHandlers struct {
	svc     ComplianceService
	catalog *compliance.Catalog
	signer  *signing.Signer
}

// auditHead returns the signed head of the tenant's audit chain. Storing it
// outside Aegis (a ticket, a Git tag, a transparency log) anchors the chain:
// a later rewrite of history no longer matches the stored head.
func (h complianceHandlers) auditHead(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	v, err := h.svc.VerifyAudit(r.Context(), tenant)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if h.signer == nil {
		writeError(w, http.StatusServiceUnavailable, "signing_unavailable", "no signing key is configured")
		return
	}
	signed, err := h.signer.Sign(struct {
		Type       string `json:"type"`
		Tenant     string `json:"tenant"`
		Seq        int64  `json:"seq"`
		Hash       string `json:"hash"`
		ChainValid bool   `json:"chain_valid"`
		SignedAt   string `json:"signed_at"`
	}{"aegis.audit-head/v1", tenant, v.HeadSeq, v.HeadHash, v.Valid, time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, signed)
}

// verifyAnchor checks a previously stored head (seq, hash) against the live chain.
func (h complianceHandlers) verifyAnchor(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req struct {
		Seq  int64  `json:"seq"`
		Hash string `json:"hash"`
	}
	if err := decodeStrict(r, &req); err != nil || req.Seq < 1 || req.Hash == "" {
		if bodyTooLarge(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_json", `body must be {"seq": <n>, "hash": "<hex>"}`)
		return
	}
	v, err := h.svc.VerifyAudit(r.Context(), tenant)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	stored, err := h.svc.AuditHashAt(r.Context(), tenant, req.Seq)
	if err != nil && !errors.Is(err, compliance.ErrNotFound) {
		h.fail(w, r, err)
		return
	}
	matches := err == nil && subtle.ConstantTimeCompare([]byte(stored), []byte(strings.ToLower(req.Hash))) == 1
	writeJSON(w, http.StatusOK, map[string]any{"matches": matches, "event_exists": err == nil,
		"chain_valid": v.Valid, "current_head_seq": v.HeadSeq, "anchored_and_intact": matches && v.Valid})
}

func (h complianceHandlers) tenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.svc == nil || h.catalog == nil {
		writeError(w, http.StatusServiceUnavailable, "compliance_unavailable", "compliance is not configured")
		return "", false
	}
	t := r.Header.Get(TenantHeader)
	if !tenantSlug.MatchString(t) {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "missing or invalid "+TenantHeader+" header")
		return "", false
	}
	return t, true
}

// actor returns the acting identity; required for state-changing requests.
// actor is the identity recorded for an action: the verified token subject
// in OIDC mode, or the X-Aegis-Actor header in development mode.
func actor(w http.ResponseWriter, r *http.Request) (string, bool) {
	if p, ok := access.FromContext(r.Context()); ok && p.Method == AuthOIDC {
		return p.Subject, true
	}
	a := r.Header.Get(ActorHeader)
	if !actorRe.MatchString(a) {
		writeError(w, http.StatusBadRequest, "invalid_actor", "missing or invalid "+ActorHeader+" header")
		return "", false
	}
	return a, true
}

// decodeStrict decodes exactly one JSON value with no unknown fields.
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected data after the JSON body")
	}
	return nil
}

// bodyTooLarge answers 413 when err came from the request size limit, so a
// client can tell "too big" from "malformed".
func bodyTooLarge(w http.ResponseWriter, err error) bool {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds the size limit")
		return true
	}
	return false
}

func (h complianceHandlers) frameworks(w http.ResponseWriter, r *http.Request) {
	if h.catalog == nil {
		writeError(w, http.StatusServiceUnavailable, "compliance_unavailable", "compliance is not configured")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"catalog_version": h.catalog.Version, "catalog_sha256": h.catalog.SHA256, "notice": h.catalog.Notice,
		"frameworks": h.catalog.Frameworks, "rules": h.catalog.Rules, "mappings": h.catalog.Mappings,
	})
}

func (h complianceHandlers) evaluate(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	var req struct {
		Source string `json:"source"`
		ScanID string `json:"scan_id"`
	}
	if err := decodeStrict(r, &req); err != nil {
		if bodyTooLarge(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_json", `body must be {"source":"inventory"} or {"source":"iac_scan","scan_id":"..."}`)
		return
	}
	var sum compliance.RunSummary
	var err error
	switch req.Source {
	case "inventory":
		sum, err = h.svc.EvaluateInventory(r.Context(), tenant, who)
	case "iac_scan":
		sum, err = h.svc.EvaluateScan(r.Context(), tenant, req.ScanID, who)
	default:
		writeError(w, http.StatusUnprocessableEntity, "invalid_source", "source must be inventory or iac_scan")
		return
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, sum)
}

func queryScope(w http.ResponseWriter, r *http.Request) (string, time.Duration, bool) {
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = compliance.ScopeObserved
	}
	stale := 7 * 24 * time.Hour
	if v := r.URL.Query().Get("stale_after"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			writeError(w, http.StatusBadRequest, "invalid_query", "stale_after must be a positive duration such as 72h")
			return "", 0, false
		}
		stale = d
	}
	return scope, stale, true
}

func (h complianceHandlers) coverage(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	scope, stale, ok := queryScope(w, r)
	if !ok {
		return
	}
	fw := r.URL.Query().Get("framework")
	if fw == "" {
		writeError(w, http.StatusBadRequest, "invalid_query", "framework is required")
		return
	}
	cov, err := h.svc.Coverage(r.Context(), tenant, fw, scope, stale)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, cov)
}

func (h complianceHandlers) control(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	scope, stale, ok := queryScope(w, r)
	if !ok {
		return
	}
	d, err := h.svc.Control(r.Context(), tenant, r.PathValue("framework"), r.PathValue("control"), scope, stale)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (h complianceHandlers) requestException(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	var req compliance.ExceptionRequest
	if err := decodeStrict(r, &req); err != nil {
		if bodyTooLarge(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_json", "body must be {rule_id, subject, justification, expires_at}")
		return
	}
	ex, err := h.svc.RequestException(r.Context(), tenant, who, req)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/compliance/exceptions/"+ex.ID)
	writeJSON(w, http.StatusCreated, ex)
}

func (h complianceHandlers) decide(decision string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := h.tenant(w, r)
		if !ok {
			return
		}
		who, ok := actor(w, r)
		if !ok {
			return
		}
		ex, err := h.svc.DecideException(r.Context(), tenant, who, r.PathValue("id"), decision)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, ex)
	}
}

func (h complianceHandlers) listExceptions(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, next, err := h.svc.ListExceptions(r.Context(), tenant, r.URL.Query().Get("after"), limit)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list, "next_cursor": next})
}

func (h complianceHandlers) auditEvents(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "invalid_query", "limit must be between 1 and 500")
			return
		}
		limit = n
	}
	var before int64
	if v := r.URL.Query().Get("before_seq"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "invalid_query", "before_seq must be a positive integer")
			return
		}
		before = n
	}
	recs, err := h.svc.AuditEvents(r.Context(), tenant, limit, before)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := map[string]any{"items": recs}
	if len(recs) == limit && len(recs) > 0 {
		out["next_before_seq"] = recs[len(recs)-1].Seq // older events: ?before_seq=<this>
	}
	writeJSON(w, http.StatusOK, out)
}

func (h complianceHandlers) verifyAudit(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	v, err := h.svc.VerifyAudit(r.Context(), tenant)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h complianceHandlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	var unavailable *opa.UnavailableError
	switch {
	case errors.Is(err, paging.ErrBadCursor): // same answer on every list
		writeError(w, http.StatusBadRequest, "invalid_cursor", "invalid cursor")
	case errors.Is(err, compliance.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found")
	case errors.Is(err, compliance.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, compliance.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
	case errors.Is(err, compliance.ErrSelfApproval):
		writeError(w, http.StatusForbidden, "self_approval", err.Error())
	case errors.Is(err, compliance.ErrConflict):
		writeError(w, http.StatusConflict, "invalid_transition", err.Error())
	case errors.Is(err, compliance.ErrScanNotReady):
		writeError(w, http.StatusConflict, "scan_not_ready", err.Error())
	case errors.As(err, &unavailable), errors.Is(err, opa.ErrUndefined):
		logging.FromContext(r.Context()).Error("policy engine unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "policy_engine_unavailable", "policy engine unavailable; no compliance result was recorded")
	case errors.Is(err, context.Canceled):
	default:
		logging.FromContext(r.Context()).Error("compliance request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
