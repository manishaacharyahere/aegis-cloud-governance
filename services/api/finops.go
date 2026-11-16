package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/finops"
)

// FinOpsService is the subset of the FinOps module used by the API.
type FinOpsService interface {
	Import(ctx context.Context, tenant, actor string, raw []byte) (finops.ImportResult, error)
	Summarize(ctx context.Context, tenant, groupBy, from, to string) (finops.Summary, error)
	TagCoverage(ctx context.Context, tenant string) (map[string]any, error)
	GenerateRecommendations(ctx context.Context, tenant, actor, asOf string) ([]finops.RecView, error)
	ListRecommendations(ctx context.Context, tenant, status string) ([]finops.RecView, error)
	DecideRecommendation(ctx context.Context, tenant, actor, id, action, implementedAt string) (finops.RecView, error)
	LatestML(ctx context.Context, tenant, kind, entity string) (finops.MLResult, error)
}

type finopsHandlers struct{ svc FinOpsService }

func (h finopsHandlers) tenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "finops_unavailable", "FinOps is not configured")
		return "", false
	}
	t := r.Header.Get(TenantHeader)
	if !tenantSlug.MatchString(t) {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "missing or invalid "+TenantHeader+" header")
		return "", false
	}
	return t, true
}

// importCost accepts a CUR-like CSV body. Large exports can be split into
// chunks (e.g. per month); rows are upserted by key so chunks are idempotent.
func (h finopsHandlers) importCost(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "CSV exceeds the import limit; split it (e.g. by month) and import each part")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_body", "could not read request body")
		return
	}
	res, err := h.svc.Import(r.Context(), tenant, who, raw)
	if err != nil {
		var verr *finops.ValidationError
		if errors.As(err, &verr) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]any{
				"code": "validation_failed", "message": "cost data failed validation; nothing was imported",
				"rows": verr.Errors, "truncated": verr.Truncated}})
			return
		}
		h.fail(w, r, err)
		return
	}
	status := http.StatusCreated
	if res.Duplicate {
		status = http.StatusOK
	}
	writeJSON(w, status, res)
}

func (h finopsHandlers) summary(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	gb := q.Get("group_by")
	if gb == "" {
		gb = "team"
	}
	s, err := h.svc.Summarize(r.Context(), tenant, gb, q.Get("from"), q.Get("to"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (h finopsHandlers) tagCoverage(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	c, err := h.svc.TagCoverage(r.Context(), tenant)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (h finopsHandlers) generate(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	var req struct {
		AsOf string `json:"as_of"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", `body must be empty or {"as_of":"YYYY-MM-DD"}`)
		return
	}
	recs, err := h.svc.GenerateRecommendations(r.Context(), tenant, who, req.AsOf)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"items": recs, "savings_basis": "projected"})
}

func (h finopsHandlers) list(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	recs, err := h.svc.ListRecommendations(r.Context(), tenant, r.URL.Query().Get("status"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": recs})
}

func (h finopsHandlers) decide(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := h.tenant(w, r)
		if !ok {
			return
		}
		who, ok := actor(w, r)
		if !ok {
			return
		}
		var req struct {
			ImplementedAt string `json:"implemented_at"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid_json", `body must be empty or {"implemented_at":"YYYY-MM-DD"}`)
			return
		}
		v, err := h.svc.DecideRecommendation(r.Context(), tenant, who, r.PathValue("id"), action, req.ImplementedAt)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func (h finopsHandlers) ml(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := h.tenant(w, r)
		if !ok {
			return
		}
		res, err := h.svc.LatestML(r.Context(), tenant, kind, r.URL.Query().Get("entity"))
		if err != nil {
			h.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

func (h finopsHandlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, finops.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found")
	case errors.Is(err, finops.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, finops.ErrNoData):
		writeError(w, http.StatusNotFound, "no_data", err.Error())
	case errors.Is(err, finops.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
	case errors.Is(err, finops.ErrConflict):
		writeError(w, http.StatusConflict, "invalid_transition", err.Error())
	case errors.Is(err, context.Canceled):
	default:
		logging.FromContext(r.Context()).Error("finops request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
