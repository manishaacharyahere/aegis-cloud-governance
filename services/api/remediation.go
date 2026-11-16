package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/remediation"
)

// RemediationService is the subset of Module H used by the API.
type RemediationService interface {
	Propose(ctx context.Context, tenant, actor string, req remediation.ProposeRequest) (remediation.View, error)
	Get(ctx context.Context, tenant, id string) (remediation.View, error)
	List(ctx context.Context, tenant, status, after string, limit int) ([]remediation.View, string, error)
	Decide(ctx context.Context, tenant, actor, id, decision, comment string) (remediation.View, error)
	Release(ctx context.Context, tenant, actor, id string) (remediation.View, error)
	Verify(ctx context.Context, tenant, actor, id string) (remediation.View, error)
}

type remediationHandlers struct{ svc RemediationService }

func (h remediationHandlers) tenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "remediation_unavailable", "remediation is not configured")
		return "", false
	}
	t := r.Header.Get(TenantHeader)
	if !tenantSlug.MatchString(t) {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "missing or invalid "+TenantHeader+" header")
		return "", false
	}
	return t, true
}

func (h remediationHandlers) templates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": remediation.Templates()})
}

func (h remediationHandlers) propose(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	var req remediation.ProposeRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "body must be a remediation proposal")
		return
	}
	v, err := h.svc.Propose(r.Context(), tenant, who, req)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (h remediationHandlers) get(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	v, err := h.svc.Get(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (h remediationHandlers) list(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	vs, next, err := h.svc.List(r.Context(), tenant, q.Get("status"), q.Get("after"), limit)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": vs, "next_cursor": next})
}

func (h remediationHandlers) decide(decision string) http.HandlerFunc {
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
			Comment string `json:"comment"`
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid_json", `body must be empty or {"comment":"..."}`)
			return
		}
		v, err := h.svc.Decide(r.Context(), tenant, who, r.PathValue("id"), decision, req.Comment)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func (h remediationHandlers) step(fn func(RemediationService) func(context.Context, string, string, string) (remediation.View, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, ok := h.tenant(w, r)
		if !ok {
			return
		}
		who, ok := actor(w, r)
		if !ok {
			return
		}
		v, err := fn(h.svc)(r.Context(), tenant, who, r.PathValue("id"))
		if err != nil {
			h.fail(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func (h remediationHandlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, remediation.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found")
	case errors.Is(err, remediation.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource or remediation not found")
	case errors.Is(err, remediation.ErrForbidden):
		writeError(w, http.StatusForbidden, "separation_of_duties", err.Error())
	case errors.Is(err, remediation.ErrStale):
		writeError(w, http.StatusConflict, "stale", err.Error())
	case errors.Is(err, remediation.ErrNotObserved):
		writeError(w, http.StatusConflict, "not_observed", err.Error())
	case errors.Is(err, remediation.ErrAmbiguous):
		writeError(w, http.StatusConflict, "ambiguous_resource", err.Error())
	case errors.Is(err, remediation.ErrConflict):
		writeError(w, http.StatusConflict, "invalid_transition", err.Error())
	case errors.Is(err, remediation.ErrInvalid), errors.Is(err, remediation.ErrNoTemplate):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
	case errors.Is(err, context.Canceled):
	default:
		logging.FromContext(r.Context()).Error("remediation request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
