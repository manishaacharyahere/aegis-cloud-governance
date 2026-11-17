package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
)

// InventoryService is the subset of the inventory module used by the API.
type InventoryService interface {
	Import(ctx context.Context, tenant string, snap inventory.Snapshot) (inventory.ImportReport, error)
	GetImport(ctx context.Context, tenant, id string) (inventory.ImportReport, error)
	ListResources(ctx context.Context, tenant string, f inventory.ListFilter) (inventory.ResourcePage, error)
	GetResource(ctx context.Context, tenant, id string) (inventory.ResourceDetail, error)
	ResourceTypes(ctx context.Context, tenant string) ([]inventory.TypeCount, error)
}

// TenantHeader selects the tenant. In OIDC mode the caller must hold a role
// in it (see auth.go); in development header mode it is caller-asserted.
const TenantHeader = "X-Aegis-Tenant"

var tenantSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

type inventoryHandlers struct{ svc InventoryService }

func (h inventoryHandlers) tenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory_unavailable", "inventory service is not configured")
		return "", false
	}
	t := r.Header.Get(TenantHeader)
	if !tenantSlug.MatchString(t) {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "missing or invalid "+TenantHeader+" header")
		return "", false
	}
	return t, true
}

// validationErrorBody extends the error envelope with per-field issues.
type validationErrorBody struct {
	Error struct {
		Code      string            `json:"code"`
		Message   string            `json:"message"`
		Issues    []inventory.Issue `json:"issues"`
		Truncated bool              `json:"truncated,omitempty"`
	} `json:"error"`
}

func (h inventoryHandlers) importSnapshot(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var snap inventory.Snapshot
	if err := dec.Decode(&snap); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "snapshot exceeds the import size limit")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_json", "request body is not a valid inventory snapshot document")
		return
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain exactly one JSON document")
		return
	}

	rep, err := h.svc.Import(r.Context(), tenant, snap)
	if err != nil {
		var verr *inventory.ValidationError
		if errors.As(err, &verr) {
			var b validationErrorBody
			b.Error.Code, b.Error.Message = "validation_failed", "snapshot failed validation"
			b.Error.Issues, b.Error.Truncated = verr.Issues, verr.Truncated
			writeJSON(w, http.StatusUnprocessableEntity, b)
			return
		}
		h.fail(w, r, err)
		return
	}
	status := http.StatusCreated
	if rep.Duplicate {
		status = http.StatusOK // idempotent replay
	}
	w.Header().Set("Location", "/api/v1/inventory/imports/"+rep.ImportID)
	writeJSON(w, status, rep)
}

func (h inventoryHandlers) getImport(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	rep, err := h.svc.GetImport(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (h inventoryHandlers) listResources(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := inventory.ListFilter{
		ResourceType: q.Get("type"),
		Environment:  q.Get("environment"),
		AccountID:    q.Get("account_id"),
		After:        q.Get("cursor"),
	}
	if v := q.Get("include_deleted"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_query", "include_deleted must be a boolean")
			return
		}
		f.IncludeDeleted = b
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, http.StatusBadRequest, "invalid_query", "limit must be between 1 and 500")
			return
		}
		f.Limit = n
	}
	page, err := h.svc.ListResources(r.Context(), tenant, f)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (h inventoryHandlers) getResource(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	d, err := h.svc.GetResource(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// fail maps domain errors to HTTP responses; unknown errors become a generic
// 500 and are logged with the request ID.
func (h inventoryHandlers) resourceTypes(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	ts, err := h.svc.ResourceTypes(r.Context(), tenant)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": ts})
}

// importTerraformState converts a Terraform state v4 file (the request body)
// into an inventory snapshot and imports it. Query parameters account_id,
// account_name and environment fill what the state does not say.
func (h inventoryHandlers) importTerraformState(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "state file exceeds the import size limit")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_body", "could not read the request body")
		return
	}
	q := r.URL.Query()
	snap, skipped, err := inventory.FromTerraformState(raw, inventory.StateOptions{
		AccountID: q.Get("account_id"), AccountName: q.Get("account_name"), Environment: q.Get("environment")})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_state", err.Error())
		return
	}
	rep, err := h.svc.Import(r.Context(), tenant, snap)
	if err != nil {
		var verr *inventory.ValidationError
		if errors.As(err, &verr) {
			var b validationErrorBody
			b.Error.Code, b.Error.Message = "validation_failed", "converted state failed validation"
			b.Error.Issues, b.Error.Truncated = verr.Issues, verr.Truncated
			writeJSON(w, http.StatusUnprocessableEntity, b)
			return
		}
		h.fail(w, r, err)
		return
	}
	if skipped == nil {
		skipped = []string{}
	}
	status := http.StatusCreated
	if rep.Duplicate {
		status = http.StatusOK
	}
	w.Header().Set("Location", "/api/v1/inventory/imports/"+rep.ImportID)
	writeJSON(w, status, map[string]any{"import": rep, "skipped": skipped})
}

func (h inventoryHandlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, inventory.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found")
	case errors.Is(err, inventory.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, inventory.ErrStaleSnapshot):
		writeError(w, http.StatusConflict, "stale_snapshot", err.Error())
	case errors.Is(err, context.Canceled):
		// Client went away; nothing useful to send.
	default:
		logging.FromContext(r.Context()).Error("inventory request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
