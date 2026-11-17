// Package api implements the Aegis HTTP control-plane API.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/signing"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/remediation"
)

// Pinger reports whether a dependency is reachable. *pgxpool.Pool satisfies it.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps are the dependencies of the HTTP API.
type Deps struct {
	Logger       *slog.Logger
	DB           Pinger
	Inventory    InventoryService // nil disables inventory routes (503)
	IaC          IaCService       // nil disables IaC routes (503)
	Compliance   ComplianceService
	Catalog      *compliance.Catalog
	Drift        DriftService
	Risk         RiskService
	FinOps       FinOpsService
	Investigator InvestigatorService
	// Auth selects OIDC or development header authentication.
	Auth Auth
	// RateLimit limits requests per caller; nil disables it.
	RateLimit *RateLimit
	// Idempotency stores Idempotency-Key responses for POST routes (nil disables).
	Idempotency IdempotencyStore
	// Settings stores per-tenant policy configuration.
	Settings SettingsStore
	// Signer signs released change sets and audit heads.
	Signer *signing.Signer
	// OutboxRequeue re-queues parked outbox events (admin endpoint).
	OutboxRequeue OutboxRequeuer
	Remediation   RemediationService
	// InvestigationWriteBudget is the write deadline for creating an
	// investigation (it may wait on a local model); 0 keeps the server default.
	InvestigationWriteBudget time.Duration
	Version                  string
	MaxBodyBytes             int64 // default per-request body limit
	MaxImportBytes           int64 // body limit for inventory imports
	MaxCostImportBytes       int64 // body limit for cost and Terraform state imports (both are large)
	// Fixtures are the Terraform fixture names a scan may use (GET /iac/fixtures).
	Fixtures []string
}

// NewHandler builds the routed, middleware-wrapped API handler. Every route
// gets an explicit body limit.
func NewHandler(d Deps) http.Handler {
	mux := http.NewServeMux()
	lim := newLimiter(nil)
	if d.RateLimit != nil {
		lim = newLimiter(d.RateLimit.Now)
	}
	handle := func(pattern string, limit int64, h http.HandlerFunc) {
		perm, ok := routePermissions[pattern]
		if !ok {
			panic("api: route " + pattern + " has no entry in routePermissions")
		}
		var inner http.Handler = h
		if strings.HasPrefix(pattern, "POST ") {
			inner = idempotent(d.Idempotency, pattern, inner)
		}
		// Rate limiting runs after authentication, so it is per user.
		mux.Handle(pattern, LimitBody(limit)(routeTag(pattern, d.RateLimit.limit(lim, pattern, d.Auth.authorize(perm, inner)))))
	}
	if d.MaxImportBytes == 0 {
		d.MaxImportBytes = d.MaxBodyBytes
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.MaxCostImportBytes == 0 {
		d.MaxCostImportBytes = d.MaxImportBytes
	}

	handle("GET /healthz", d.MaxBodyBytes, handleLiveness)
	handle("GET /readyz", d.MaxBodyBytes, handleReadiness(d.DB))
	handle("GET /api/v1/version", d.MaxBodyBytes, handleVersion(d.Version))
	ac := accessHandlers{auth: d.Auth}
	th := tenantHandlers{svc: d.Settings}
	handle("GET /api/v1/tenant/policy-config", d.MaxBodyBytes, th.getPolicyConfig)
	handle("PUT /api/v1/tenant/policy-config", d.MaxBodyBytes, th.putPolicyConfig)
	handle("POST /api/v1/admin/outbox/requeue", d.MaxBodyBytes, opsHandlers{requeue: d.OutboxRequeue}.requeueOutbox)
	handle("GET /api/v1/auth/config", d.MaxBodyBytes, ac.config)
	handle("GET /api/v1/me", d.MaxBodyBytes, ac.me)
	handle("GET /api/v1/me/tenants", d.MaxBodyBytes, ac.tenants)
	handle("GET /api/v1/openapi.yaml", d.MaxBodyBytes, serveOpenAPI)
	handle("GET /api/v1/access/bindings", d.MaxBodyBytes, ac.list)
	handle("POST /api/v1/access/bindings", d.MaxBodyBytes, ac.change(true))
	handle("DELETE /api/v1/access/bindings", d.MaxBodyBytes, ac.change(false))

	inv := inventoryHandlers{svc: d.Inventory}
	handle("POST /api/v1/inventory/import", d.MaxImportBytes, inv.importSnapshot)
	handle("GET /api/v1/inventory/imports/{id}", d.MaxBodyBytes, inv.getImport)
	handle("GET /api/v1/resources", d.MaxBodyBytes, inv.listResources)
	handle("GET /api/v1/resources/{id}", d.MaxBodyBytes, inv.getResource)
	handle("GET /api/v1/resources/types", d.MaxBodyBytes, inv.resourceTypes)
	// State files are large; they share the cost-import limit.
	handle("POST /api/v1/inventory/import/terraform-state", d.MaxCostImportBytes, inv.importTerraformState)
	scans := iacHandlers{svc: d.IaC, fixtures: d.Fixtures}
	handle("GET /api/v1/iac/fixtures", d.MaxBodyBytes, scans.listFixtures)
	handle("GET /api/v1/iac/scans", d.MaxBodyBytes, scans.listScans)
	handle("POST /api/v1/iac/scans", d.MaxBodyBytes, scans.createScan)
	handle("GET /api/v1/iac/scans/{id}", d.MaxBodyBytes, scans.getScan)
	comp := complianceHandlers{svc: d.Compliance, catalog: d.Catalog, signer: d.Signer}
	handle("GET /api/v1/audit/head", d.MaxBodyBytes, comp.auditHead)
	handle("POST /api/v1/audit/anchors/verify", d.MaxBodyBytes, comp.verifyAnchor)
	handle("GET /api/v1/signing-key", d.MaxBodyBytes, func(w http.ResponseWriter, _ *http.Request) {
		if d.Signer == nil {
			writeError(w, http.StatusServiceUnavailable, "signing_unavailable", "no signing key is configured")
			return
		}
		writeJSON(w, http.StatusOK, d.Signer.Public())
	})
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
	handle("GET /api/v1/drift/reports", d.MaxBodyBytes, dr.listReports)
	rk := riskHandlers{svc: d.Risk}
	handle("POST /api/v1/risk/assessments", d.MaxBodyBytes, rk.assess)
	handle("GET /api/v1/risk/assessments/{id}", d.MaxBodyBytes, rk.getRun)
	handle("GET /api/v1/risk/attack-paths", d.MaxBodyBytes, rk.attackPaths)
	fo := finopsHandlers{svc: d.FinOps}
	handle("POST /api/v1/cost/import", d.MaxCostImportBytes, fo.importCost)
	handle("GET /api/v1/cost/summary", d.MaxBodyBytes, fo.summary)
	handle("GET /api/v1/cost/tag-coverage", d.MaxBodyBytes, fo.tagCoverage)
	handle("GET /api/v1/cost/forecast", d.MaxBodyBytes, fo.ml("forecast"))
	handle("GET /api/v1/cost/anomalies", d.MaxBodyBytes, fo.ml("anomaly"))
	handle("POST /api/v1/recommendations", d.MaxBodyBytes, fo.generate)
	handle("GET /api/v1/recommendations", d.MaxBodyBytes, fo.list)
	handle("POST /api/v1/recommendations/{id}/accept", d.MaxBodyBytes, fo.decide("accept"))
	handle("POST /api/v1/recommendations/{id}/dismiss", d.MaxBodyBytes, fo.decide("dismiss"))
	handle("POST /api/v1/recommendations/{id}/implement", d.MaxBodyBytes, fo.decide("implement"))
	ig := investigatorHandlers{svc: d.Investigator, writeBudget: d.InvestigationWriteBudget}
	handle("GET /api/v1/assistant/status", d.MaxBodyBytes, ig.status)
	handle("POST /api/v1/investigations", d.MaxBodyBytes, ig.create)
	handle("GET /api/v1/investigations/{id}", d.MaxBodyBytes, ig.get)
	rm := remediationHandlers{svc: d.Remediation}
	handle("GET /api/v1/remediation/templates", d.MaxBodyBytes, rm.templates)
	handle("POST /api/v1/remediations", d.MaxBodyBytes, rm.propose)
	handle("GET /api/v1/remediations", d.MaxBodyBytes, rm.list)
	handle("GET /api/v1/remediations/{id}", d.MaxBodyBytes, rm.get)
	handle("POST /api/v1/remediations/{id}/approve", d.MaxBodyBytes, rm.decide("approve"))
	handle("POST /api/v1/remediations/{id}/reject", d.MaxBodyBytes, rm.decide("reject"))
	handle("POST /api/v1/remediations/{id}/release", d.MaxBodyBytes, rm.step(func(s RemediationService) func(context.Context, string, string, string) (remediation.View, error) {
		return s.Release
	}))
	handle("POST /api/v1/remediations/{id}/verify", d.MaxBodyBytes, rm.step(func(s RemediationService) func(context.Context, string, string, string) (remediation.View, error) {
		return s.Verify
	}))
	// No catch-all route: it would shadow the mux's automatic 405 responses.

	// otelhttp is outermost so the request span exists before logging, and
	// every response (including 404/405) is measured.
	return otelhttp.NewHandler(Chain(mux,
		RequestContext(d.Logger),
		Recover,
		d.Auth.authenticate,
		SecurityHeaders,
	), "http.server",
		// A fixed server name: the Host header is client-controlled and must not become a metric label.
		otelhttp.WithServerName("aegis-api"),
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string { return r.Method }))
}

// routeTag names the span after the route pattern (low cardinality: IDs are
// not in span names or metric labels) and labels the request metrics with it.
func routeTag(pattern string, next http.Handler) http.Handler {
	route := pattern
	if i := strings.IndexByte(pattern, ' '); i >= 0 {
		route = pattern[i+1:]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanFromContext(r.Context())
		span.SetName(pattern)
		span.SetAttributes(semconv.HTTPRoute(route))
		if l, ok := otelhttp.LabelerFromContext(r.Context()); ok {
			l.Add(semconv.HTTPRoute(route))
		}
		next.ServeHTTP(w, r)
	})
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
