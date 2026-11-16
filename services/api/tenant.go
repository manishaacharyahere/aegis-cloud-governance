package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/tenancy"
)

// SettingsStore reads and writes per-tenant settings.
type SettingsStore interface {
	Get(ctx context.Context, tenant string) (tenancy.PolicyConfig, error)
	Put(ctx context.Context, tenant, actor string, c tenancy.PolicyConfig) error
}

type tenantHandlers struct{ svc SettingsStore }

func (h tenantHandlers) getPolicyConfig(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "settings_unavailable", "tenant settings are not configured")
		return
	}
	c, err := h.svc.Get(r.Context(), r.Header.Get(TenantHeader))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy_config": c,
		"note": "Empty fields use the policy defaults. Changes apply to the next evaluation; stored results are not rewritten."})
}

func (h tenantHandlers) putPolicyConfig(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "settings_unavailable", "tenant settings are not configured")
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	var c tenancy.PolicyConfig
	if err := decodeStrict(r, &c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "body must be a policy config object")
		return
	}
	if err := h.svc.Put(r.Context(), r.Header.Get(TenantHeader), who, c); err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy_config": c})
}

func (h tenantHandlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, tenancy.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
	case errors.Is(err, tenancy.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found")
	default:
		logging.FromContext(r.Context()).Error("tenant settings request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
