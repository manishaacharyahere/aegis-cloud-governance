package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/iac"
)

// IaCService is the subset of the IaC module used by the API.
type IaCService interface {
	Enqueue(ctx context.Context, tenant, actor, fixture, idempotencyKey string) (iac.Scan, bool, error)
	Get(ctx context.Context, tenant, id string) (iac.Report, error)
	List(ctx context.Context, tenant, after string, limit int) ([]iac.Scan, string, error)
}

var fixtureRef = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type iacHandlers struct {
	svc      IaCService
	fixtures []string
}

// listFixtures returns the Terraform fixtures a scan may name.
func (h iacHandlers) listFixtures(w http.ResponseWriter, _ *http.Request) {
	fs := h.fixtures
	if fs == nil {
		fs = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": fs})
}

func (h iacHandlers) listScans(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	scans, next, err := h.svc.List(r.Context(), tenant, r.URL.Query().Get("after"), limit)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": scans, "next_cursor": next})
}

type scanRequest struct {
	Source struct {
		Type string `json:"type"`
		Ref  string `json:"ref"`
	} `json:"source"`
}

func (h iacHandlers) tenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "iac_unavailable", "IaC scanning is not configured")
		return "", false
	}
	t := r.Header.Get(TenantHeader)
	if !tenantSlug.MatchString(t) {
		writeError(w, http.StatusBadRequest, "invalid_tenant", "missing or invalid "+TenantHeader+" header")
		return "", false
	}
	return t, true
}

// createScan queues a scan and returns 202; workers execute it asynchronously.
func (h iacHandlers) createScan(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	who, ok := actor(w, r)
	if !ok {
		return
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req scanRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "body must be {\"source\":{\"type\":\"fixture\",\"ref\":\"<name>\"}}")
		return
	}
	if req.Source.Type != "fixture" || !fixtureRef.MatchString(req.Source.Ref) {
		writeError(w, http.StatusUnprocessableEntity, "invalid_source", "source.type must be \"fixture\" and source.ref a fixture name")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key != "" && !idemKeyRe.MatchString(key) {
		writeError(w, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must be 1-128 safe characters")
		return
	}
	scan, created, err := h.svc.Enqueue(r.Context(), tenant, who, req.Source.Ref, key)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.Header().Set("Location", "/api/v1/iac/scans/"+scan.ID)
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	writeJSON(w, status, scan)
}

func (h iacHandlers) getScan(w http.ResponseWriter, r *http.Request) {
	tenant, ok := h.tenant(w, r)
	if !ok {
		return
	}
	rep, err := h.svc.Get(r.Context(), tenant, r.PathValue("id"))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func (h iacHandlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, iac.ErrTenantNotFound):
		writeError(w, http.StatusNotFound, "tenant_not_found", "tenant not found")
	case errors.Is(err, iac.ErrInvalidCursor):
		writeError(w, http.StatusBadRequest, "invalid_cursor", "invalid cursor")
	case errors.Is(err, iac.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "scan not found")
	case errors.Is(err, iac.ErrIdempotencyConflict):
		writeError(w, http.StatusUnprocessableEntity, "idempotency_key_reused", "Idempotency-Key was already used for a different request")
	case errors.Is(err, context.Canceled):
	default:
		logging.FromContext(r.Context()).Error("iac request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
