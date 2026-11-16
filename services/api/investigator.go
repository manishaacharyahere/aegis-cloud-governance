package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/investigator"
)

// InvestigatorService is the subset of Module G used by the API.
type InvestigatorService interface {
	Status() map[string]any
	Investigate(ctx context.Context, tenant, actor string, req investigator.Request) (investigator.Investigation, error)
	Get(ctx context.Context, tenant, id string) (investigator.Investigation, error)
}

type investigatorHandlers struct {
	svc InvestigatorService
	// writeBudget extends the write deadline of POST /investigations past the
	// server-wide WriteTimeout so a slow local model cannot cut off the reply.
	writeBudget time.Duration
}

func (h investigatorHandlers) tenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "investigator_unavailable", "investigations are not configured")
		return "", false
	}
	t := r.Header.Get(TenantHeader)
	if !tenantSlug.MatchString(t) {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "missing or invalid "+TenantHeader+" header")
		return "", false
	}
	return t, true
}

func (h investigatorHandlers) status(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.tenant(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, h.svc.Status())
}

func (h investigatorHandlers) create(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	var req investigator.Request
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", `body must be {"resource_id": "...", "account_id": "optional", "question": "optional"}`)
		return
	}
	if h.writeBudget > 0 {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(h.writeBudget))
	}
	inv, err := h.svc.Investigate(r.Context(), tenant, who, req)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, inv)
}

func (h investigatorHandlers) get(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	inv, err := h.svc.Get(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

func (h investigatorHandlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, investigator.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found")
	case errors.Is(err, investigator.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource or investigation not found")
	case errors.Is(err, investigator.ErrAmbiguous):
		writeError(w, http.StatusConflict, "ambiguous_resource", err.Error())
	case errors.Is(err, investigator.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
	case errors.Is(err, context.Canceled):
	default:
		logging.FromContext(r.Context()).Error("investigation request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
