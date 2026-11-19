package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/paging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/drift"
)

// DriftService is the subset of the drift module used by the API.
type DriftService interface {
	ApproveBaseline(ctx context.Context, tenant, accountID, actor, note string) (drift.Baseline, error)
	ListBaselines(ctx context.Context, tenant string) ([]drift.Baseline, error)
	Compare(ctx context.Context, tenant, accountID, actor string) (drift.Report, error)
	GetReport(ctx context.Context, tenant, id, category, minSeverity string) (drift.Report, error)
	ListReports(ctx context.Context, tenant, after string, limit int) ([]drift.Report, string, error)
}

type driftHandlers struct{ svc DriftService }

func (h driftHandlers) tenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "drift_unavailable", "drift detection is not configured")
		return "", false
	}
	t := r.Header.Get(TenantHeader)
	if !tenantSlug.MatchString(t) {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "missing or invalid "+TenantHeader+" header")
		return "", false
	}
	return t, true
}

func (h driftHandlers) approveBaseline(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	var req struct {
		AccountID string `json:"account_id"`
		Note      string `json:"note"`
	}
	if err := decodeStrict(r, &req); err != nil {
		if bodyTooLarge(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_json", `body must be {"account_id":"<optional>","note":"<optional>"}`)
		return
	}
	b, err := h.svc.ApproveBaseline(r.Context(), tenant, req.AccountID, who, req.Note)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, b)
}

func (h driftHandlers) listBaselines(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	list, err := h.svc.ListBaselines(r.Context(), tenant)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list})
}

func (h driftHandlers) listReports(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, next, err := h.svc.ListReports(r.Context(), tenant, r.URL.Query().Get("after"), limit)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list, "next_cursor": next})
}

func (h driftHandlers) compare(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	var req struct {
		AccountID string `json:"account_id"`
	}
	if err := decodeStrict(r, &req); err != nil {
		if bodyTooLarge(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_json", `body must be {"account_id":"<optional>"}`)
		return
	}
	rep, err := h.svc.Compare(r.Context(), tenant, req.AccountID, who)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/drift/reports/"+rep.ID)
	writeJSON(w, http.StatusCreated, rep)
}

func (h driftHandlers) getReport(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	rep, err := h.svc.GetReport(r.Context(), tenant, r.PathValue("id"), q.Get("category"), q.Get("min_severity"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (h driftHandlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	var unavailable *opa.UnavailableError
	switch {
	case errors.Is(err, paging.ErrBadCursor): // same answer on every list
		writeError(w, http.StatusBadRequest, "invalid_cursor", "invalid cursor")
	case errors.Is(err, drift.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found")
	case errors.Is(err, drift.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, drift.ErrNoBaseline):
		writeError(w, http.StatusConflict, "no_baseline", err.Error())
	case errors.Is(err, drift.ErrNoInventory):
		writeError(w, http.StatusConflict, "no_inventory", err.Error())
	case errors.Is(err, drift.ErrAmbiguous): // same answer as investigator and remediation
		writeError(w, http.StatusConflict, "ambiguous_resource", err.Error())
	case errors.Is(err, drift.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
	case errors.As(err, &unavailable), errors.Is(err, opa.ErrUndefined):
		logging.FromContext(r.Context()).Error("policy engine unavailable", "error", err)
		writeError(w, http.StatusServiceUnavailable, "policy_engine_unavailable", "policy engine unavailable; no drift report was recorded")
	case errors.Is(err, context.Canceled):
	default:
		logging.FromContext(r.Context()).Error("drift request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
