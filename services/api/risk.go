package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/risk"
)

// RiskService is the subset of the risk module used by the API.
type RiskService interface {
	Assess(ctx context.Context, tenant, actor string, w risk.Weights) (risk.Run, error)
	GetRun(ctx context.Context, tenant, id, minBand string, limit int) (risk.Run, error)
	AttackPaths(ctx context.Context, tenant string, minSensitivity, limit int) ([]risk.Path, error)
}

type riskHandlers struct{ svc RiskService }

func (h riskHandlers) tenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "risk_unavailable", "risk intelligence is not configured")
		return "", false
	}
	t := r.Header.Get(TenantHeader)
	if !tenantSlug.MatchString(t) {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "missing or invalid "+TenantHeader+" header")
		return "", false
	}
	return t, true
}

// assess scores current findings; an optional body overrides the weights.
func (h riskHandlers) assess(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	var req struct {
		Weights *risk.Weights `json:"weights"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", `body must be empty or {"weights":{...}}`)
		return
	}
	weights := risk.DefaultWeights()
	if req.Weights != nil {
		weights = *req.Weights
	}
	run, err := h.svc.Assess(r.Context(), tenant, who, weights)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if len(run.Assessments) > 20 {
		run.Assessments = run.Assessments[:20] // full list via GET
	}
	w.Header().Set("Location", "/api/v1/risk/assessments/"+run.ID)
	writeJSON(w, http.StatusCreated, run)
}

func (h riskHandlers) getRun(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limit, ok := intQuery(w, r, "limit", 100, 1, 1000)
	if !ok {
		return
	}
	run, err := h.svc.GetRun(r.Context(), tenant, r.PathValue("id"), r.URL.Query().Get("min_band"), limit)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (h riskHandlers) attackPaths(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	minSens, ok := intQuery(w, r, "min_sensitivity", 50, 0, 100)
	if !ok {
		return
	}
	limit, ok := intQuery(w, r, "limit", 50, 1, 500)
	if !ok {
		return
	}
	paths, err := h.svc.AttackPaths(r.Context(), tenant, minSens, limit)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": paths, "count": len(paths),
		"model": "internet -> exposed entry -> routes_to/assumes/reads_from/writes_to/admin-role -> data store; max depth 6"})
}

func intQuery(w http.ResponseWriter, r *http.Request, name string, def, lo, hi int) (int, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		writeError(w, http.StatusBadRequest, "invalid_query", name+" must be between "+strconv.Itoa(lo)+" and "+strconv.Itoa(hi))
		return 0, false
	}
	return n, true
}

func (h riskHandlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, risk.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found")
	case errors.Is(err, risk.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, risk.ErrNoEvaluation):
		writeError(w, http.StatusConflict, "no_evaluation", err.Error())
	case errors.Is(err, risk.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
	case errors.Is(err, context.Canceled):
	default:
		logging.FromContext(r.Context()).Error("risk request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
