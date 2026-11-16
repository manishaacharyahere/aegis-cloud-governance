// Package api implements the Aegis HTTP control-plane API.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
)

// Pinger reports whether a dependency is reachable. *pgxpool.Pool satisfies it.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps are the dependencies of the HTTP API.
type Deps struct {
	Logger         *slog.Logger
	DB             Pinger
	Inventory      InventoryService // nil disables inventory routes (503)
	IaC            IaCService       // nil disables IaC routes (503)
	Compliance     ComplianceService
	Catalog        *compliance.Catalog
	Drift          DriftService
	Risk           RiskService
	Version        string
	MaxBodyBytes   int64 // default per-request body limit
	MaxImportBytes int64 // body limit for inventory imports
}

// NewHandler builds the routed, middleware-wrapped API handler. Every route
// gets an explicit body limit.
func NewHandler(d Deps) http.Handler {
	mux := http.NewServeMux()
	handle := func(pattern string, limit int64, h http.HandlerFunc) {
		mux.Handle(pattern, LimitBody(limit)(h))
	}
	if d.MaxImportBytes == 0 {
		d.MaxImportBytes = d.MaxBodyBytes
	}

	handle("GET /healthz", d.MaxBodyBytes, handleLiveness)
	handle("GET /readyz", d.MaxBodyBytes, handleReadiness(d.DB))
	handle("GET /api/v1/version", d.MaxBodyBytes, handleVersion(d.Version))

	inv := inventoryHandlers{svc: d.Inventory}
	handle("POST /api/v1/inventory/import", d.MaxImportBytes, inv.importSnapshot)
	handle("GET /api/v1/inventory/imports/{id}", d.MaxBodyBytes, inv.getImport)
	handle("GET /api/v1/resources", d.MaxBodyBytes, inv.listResources)
	handle("GET /api/v1/resources/{id}", d.MaxBodyBytes, inv.getResource)
	scans := iacHandlers{svc: d.IaC}
	handle("POST /api/v1/iac/scans", d.MaxBodyBytes, scans.createScan)
	handle("GET /api/v1/iac/scans/{id}", d.MaxBodyBytes, scans.getScan)
	comp := complianceHandlers{svc: d.Compliance, catalog: d.Catalog}
	handle("GET /api/v1/compliance/frameworks", d.MaxBodyBytes, comp.frameworks)
	handle("POST /api/v1/compliance/evaluations", d.MaxBodyBytes, comp.evaluate)
	handle("GET /api/v1/compliance/coverage", d.MaxBodyBytes, comp.coverage)
	handle("GET /api/v1/compliance/controls/{framework}/{control}", d.MaxBodyBytes, comp.control)
	handle("GET /api/v1/compliance/exceptions", d.MaxBodyBytes, comp.listExceptions)
	handle("POST /api/v1/compliance/exceptions", d.MaxBodyBytes, comp.requestException)
	handle("POST /api/v1/compliance/exceptions/{id}/approve", d.MaxBodyBytes, comp.decide(compliance.DecisionApprove))
	handle("POST /api/v1/compliance/exceptions/{id}/reject", d.MaxBodyBytes, comp.decide(compliance.DecisionReject))
	handle("POST /api/v1/compliance/exceptions/{id}/revoke", d.MaxBodyBytes, comp.decide(compliance.DecisionRevoke))
	handle("GET /api/v1/audit/events", d.MaxBodyBytes, comp.auditEvents)
	handle("GET /api/v1/audit/verify", d.MaxBodyBytes, comp.verifyAudit)
	dr := driftHandlers{svc: d.Drift}
	handle("POST /api/v1/drift/baselines", d.MaxBodyBytes, dr.approveBaseline)
	handle("GET /api/v1/drift/baselines", d.MaxBodyBytes, dr.listBaselines)
	handle("POST /api/v1/drift/compare", d.MaxBodyBytes, dr.compare)
	handle("GET /api/v1/drift/reports/{id}", d.MaxBodyBytes, dr.getReport)
	rk := riskHandlers{svc: d.Risk}
	handle("POST /api/v1/risk/assessments", d.MaxBodyBytes, rk.assess)
	handle("GET /api/v1/risk/assessments/{id}", d.MaxBodyBytes, rk.getRun)
	handle("GET /api/v1/risk/attack-paths", d.MaxBodyBytes, rk.attackPaths)
	// No catch-all route: it would shadow the mux's automatic 405 responses.

	return Chain(mux,
		RequestContext(d.Logger),
		Recover,
		SecurityHeaders,
	)
}

// NewServer returns an http.Server with explicit timeouts so slow clients
// cannot hold connections open indefinitely.
func NewServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

func handleLiveness(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleReadiness(db Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		checks := map[string]string{"database": "ok"}
		status := http.StatusOK
		if db == nil {
			checks["database"] = "unconfigured"
			status = http.StatusServiceUnavailable
		} else if err := db.Ping(ctx); err != nil {
			// Log the cause; return only a generic state to the caller.
			logging.FromContext(r.Context()).Warn("readiness check failed", "check", "database", "error", err)
			checks["database"] = "unavailable"
			status = http.StatusServiceUnavailable
		}
		state := "ready"
		if status != http.StatusOK {
			state = "not_ready"
		}
		writeJSON(w, status, map[string]any{"status": state, "checks": checks})
	}
}

func handleVersion(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"service": "aegis-api", "version": version})
	}
}

// ErrorBody is the uniform error envelope returned by every endpoint.
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	var b ErrorBody
	b.Error.Code, b.Error.Message = code, msg
	writeJSON(w, status, b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
