package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
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
	ListExceptions(ctx context.Context, tenant string) ([]compliance.ExceptionView, error)
	AuditEvents(ctx context.Context, tenant string, limit int) ([]audit.Record, error)
	VerifyAudit(ctx context.Context, tenant string) (audit.Verification, error)
}

// ActorHeader identifies who performs an action. TEMPORARY: caller-asserted
// until authentication exists (see security/threat-model.md).
const ActorHeader = "X-Aegis-Actor"

var actorRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{0,63}$`)

type complianceHandlers struct {
	svc     ComplianceService
	catalog *compliance.Catalog
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
func actor(w http.ResponseWriter, r *http.Request) (string, bool) {
	a := r.Header.Get(ActorHeader)
	if !actorRe.MatchString(a) {
		writeError(w, http.StatusBadRequest, "invalid_actor", "missing or invalid "+ActorHeader+" header")
		return "", false
	}
	return a, true
}

func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
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
	list, err := h.svc.ListExceptions(r.Context(), tenant)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list})
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
	recs, err := h.svc.AuditEvents(r.Context(), tenant, limit)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": recs})
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
