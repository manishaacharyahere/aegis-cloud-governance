package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/access"
)

// Authentication modes.
const (
	AuthOIDC       = "oidc"
	AuthDevHeaders = "dev-headers" // development and tests only; refused in production by config
)

// TokenVerifier verifies bearer tokens.
type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (access.Principal, error)
}

// RoleStore resolves and manages role bindings.
type RoleStore interface {
	RolesFor(ctx context.Context, tenant, subject string) ([]string, error)
	List(ctx context.Context, tenant string) ([]access.Binding, error)
	Grant(ctx context.Context, tenant, actor, subject, role string) error
	Revoke(ctx context.Context, tenant, actor, subject, role string) error
	Memberships(ctx context.Context, subject string, all bool) ([]access.Membership, error)
}

// Auth configures authentication and authorization.
type Auth struct {
	Mode     string // AuthOIDC or AuthDevHeaders; empty means AuthDevHeaders
	Verifier TokenVerifier
	Roles    RoleStore
	Issuer   string // published to the dashboard by /api/v1/auth/config
	ClientID string
}

// routePermissions is the single table of what each route requires.
// NewHandler refuses to register a route that is missing here.
var routePermissions = map[string]access.Permission{
	"GET /healthz":                      access.Public,
	"GET /readyz":                       access.Public,
	"GET /api/v1/version":               access.Public,
	"GET /api/v1/auth/config":           access.Public,
	"GET /api/v1/signing-key":           access.Public,
	"GET /api/v1/audit/head":            access.Read,
	"POST /api/v1/audit/anchors/verify": access.Read,

	"GET /api/v1/me":                                access.Signed,
	"GET /api/v1/me/tenants":                        access.Signed,
	"GET /api/v1/iac/fixtures":                      access.Signed,
	"GET /api/v1/openapi.yaml":                      access.Public,
	"GET /api/v1/compliance/frameworks":             access.Signed,
	"GET /api/v1/remediation/templates":             access.Signed,
	"GET /api/v1/access/bindings":                   access.Admin,
	"POST /api/v1/admin/outbox/requeue":             access.Admin,
	"GET /api/v1/tenant/policy-config":              access.Read,
	"PUT /api/v1/tenant/policy-config":              access.Admin,
	"POST /api/v1/access/bindings":                  access.Admin,
	"DELETE /api/v1/access/bindings":                access.Admin,
	"POST /api/v1/inventory/import":                 access.Operate,
	"GET /api/v1/inventory/imports/{id}":            access.Read,
	"GET /api/v1/resources":                         access.Read,
	"GET /api/v1/resources/{id}":                    access.Read,
	"GET /api/v1/resources/types":                   access.Read,
	"POST /api/v1/inventory/import/terraform-state": access.Operate,
	"GET /api/v1/iac/scans":                         access.Read,
	"POST /api/v1/iac/scans":                        access.Operate,
	"GET /api/v1/iac/scans/{id}":                    access.Read,

	"POST /api/v1/compliance/evaluations":                   access.Operate,
	"GET /api/v1/compliance/coverage":                       access.Read,
	"GET /api/v1/compliance/controls/{framework}/{control}": access.Read,
	"GET /api/v1/compliance/exceptions":                     access.Read,
	"POST /api/v1/compliance/exceptions":                    access.Operate,
	"POST /api/v1/compliance/exceptions/{id}/approve":       access.Approve,
	"POST /api/v1/compliance/exceptions/{id}/reject":        access.Approve,
	"POST /api/v1/compliance/exceptions/{id}/revoke":        access.Approve,
	"GET /api/v1/audit/events":                              access.Read,
	"GET /api/v1/audit/verify":                              access.Read,

	"POST /api/v1/drift/baselines":      access.Approve,
	"GET /api/v1/drift/baselines":       access.Read,
	"POST /api/v1/drift/compare":        access.Operate,
	"GET /api/v1/drift/reports/{id}":    access.Read,
	"GET /api/v1/drift/reports":         access.Read,
	"POST /api/v1/risk/assessments":     access.Operate,
	"GET /api/v1/risk/assessments/{id}": access.Read,
	"GET /api/v1/risk/attack-paths":     access.Read,

	"POST /api/v1/cost/import":                    access.Operate,
	"GET /api/v1/cost/summary":                    access.Read,
	"GET /api/v1/cost/tag-coverage":               access.Read,
	"GET /api/v1/cost/forecast":                   access.Read,
	"GET /api/v1/cost/anomalies":                  access.Read,
	"POST /api/v1/recommendations":                access.Operate,
	"GET /api/v1/recommendations":                 access.Read,
	"POST /api/v1/recommendations/{id}/accept":    access.Operate,
	"POST /api/v1/recommendations/{id}/dismiss":   access.Operate,
	"POST /api/v1/recommendations/{id}/implement": access.Operate,

	"GET /api/v1/assistant/status":           access.Read,
	"POST /api/v1/investigations":            access.Operate,
	"GET /api/v1/investigations/{id}":        access.Read,
	"POST /api/v1/remediations":              access.Operate,
	"GET /api/v1/remediations":               access.Read,
	"GET /api/v1/remediations/{id}":          access.Read,
	"POST /api/v1/remediations/{id}/approve": access.Approve,
	"POST /api/v1/remediations/{id}/reject":  access.Approve,
	"POST /api/v1/remediations/{id}/release": access.Approve,
	"POST /api/v1/remediations/{id}/verify":  access.Operate,
}

// authenticate puts the caller in the request context. With OIDC, a missing
// or invalid token leaves no principal (authorize then answers 401); an
// unreachable provider is remembered so authorize can answer 503.
func (a Auth) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Mode != AuthOIDC {
			// Development mode: the actor header is trusted and every permission granted.
			r = r.WithContext(access.WithPrincipal(r.Context(), access.Principal{Subject: r.Header.Get(ActorHeader), Method: AuthDevHeaders}))
			next.ServeHTTP(w, r)
			return
		}
		h := r.Header.Get("Authorization")
		if raw, ok := strings.CutPrefix(h, "Bearer "); ok && raw != "" && a.Verifier != nil {
			p, err := a.Verifier.Verify(r.Context(), strings.TrimSpace(raw))
			switch {
			case err == nil:
				r = r.WithContext(access.WithPrincipal(r.Context(), p))
			case errors.Is(err, access.ErrProviderUnavailable):
				r = r.WithContext(context.WithValue(r.Context(), providerDownKey{}, true))
				logging.FromContext(r.Context()).Warn("identity provider unavailable", "error", err)
			default:
				logging.FromContext(r.Context()).Info("rejected bearer token", "error", err)
			}
		}
		next.ServeHTTP(w, r)
	})
}

type providerDownKey struct{}

// localClient reports whether the direct peer is on loopback or a private
// network (RFC 1918 / RFC 4193, e.g. the Docker network).
func localClient(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// authorize enforces the route's permission for the tenant in X-Aegis-Tenant.
func (a Auth) authorize(perm access.Permission, next http.Handler) http.Handler {
	if perm == access.Public {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := access.FromContext(r.Context())
		if !ok {
			if down, _ := r.Context().Value(providerDownKey{}).(bool); down {
				writeError(w, http.StatusServiceUnavailable, "identity_provider_unavailable", "cannot verify tokens right now; try again")
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="aegis"`)
			writeError(w, http.StatusUnauthorized, "unauthenticated", "a valid bearer token is required")
			return
		}
		// Development mode trusts the actor header and grants everything, so it
		// only accepts clients on loopback or private networks: an accidentally
		// exposed development API is not open to the internet.
		if p.Method == AuthDevHeaders && !localClient(r) {
			writeError(w, http.StatusForbidden, "dev_mode_local_only", "this API runs in development mode and only accepts local clients")
			return
		}
		if perm == access.Signed || p.Method == AuthDevHeaders {
			next.ServeHTTP(w, r)
			return
		}
		tenant := r.Header.Get(TenantHeader)
		if !tenantSlug.MatchString(tenant) {
			writeError(w, http.StatusBadRequest, "invalid_tenant", "missing or invalid "+TenantHeader+" header")
			return
		}
		if a.Roles == nil {
			writeError(w, http.StatusForbidden, "forbidden", "no role store configured")
			return
		}
		roles, err := a.Roles.RolesFor(r.Context(), tenant, p.Subject)
		if err != nil {
			logging.FromContext(r.Context()).Error("role lookup failed", "error", err)
			writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
		if !access.Allows(roles, perm) {
			// Same answer for unknown tenants and missing roles: tenants cannot be enumerated.
			writeError(w, http.StatusForbidden, "forbidden", "your roles in this tenant do not allow this action ("+string(perm)+")")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type accessHandlers struct{ auth Auth }

// config tells the dashboard how to sign in. It reveals nothing secret: the
// issuer and client ID are public in any OIDC deployment.
func (h accessHandlers) config(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"mode": AuthDevHeaders}
	if h.auth.Mode == AuthOIDC {
		out = map[string]any{"mode": AuthOIDC, "issuer": h.auth.Issuer, "client_id": h.auth.ClientID}
	}
	writeJSON(w, http.StatusOK, out)
}

func (h accessHandlers) me(w http.ResponseWriter, r *http.Request) {
	p, _ := access.FromContext(r.Context())
	out := map[string]any{"subject": p.Subject, "name": p.Name, "method": p.Method}
	if t := r.Header.Get(TenantHeader); tenantSlug.MatchString(t) {
		roles := []string{}
		switch {
		case p.Method == AuthDevHeaders:
			roles = access.Roles()
		case h.auth.Roles != nil:
			if rs, err := h.auth.Roles.RolesFor(r.Context(), t, p.Subject); err == nil && rs != nil {
				roles = rs
			}
		}
		out["tenant"], out["roles"] = t, roles
	}
	writeJSON(w, http.StatusOK, out)
}

// tenants lists the tenants the caller holds a role in (for the tenant picker).
func (h accessHandlers) tenants(w http.ResponseWriter, r *http.Request) {
	if h.auth.Roles == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []access.Membership{}})
		return
	}
	p, _ := access.FromContext(r.Context())
	ms, err := h.auth.Roles.Memberships(r.Context(), p.Subject, p.Method == AuthDevHeaders)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": ms})
}

func (h accessHandlers) list(w http.ResponseWriter, r *http.Request) {
	if h.auth.Roles == nil {
		writeError(w, http.StatusServiceUnavailable, "access_unavailable", "role bindings are not configured")
		return
	}
	bs, err := h.auth.Roles.List(r.Context(), r.Header.Get(TenantHeader))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": bs})
}

func (h accessHandlers) change(grant bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.auth.Roles == nil {
			writeError(w, http.StatusServiceUnavailable, "access_unavailable", "role bindings are not configured")
			return
		}
		who, ok := actor(w, r)
		if !ok {
			return
		}
		var req struct {
			Subject string `json:"subject"`
			Role    string `json:"role"`
		}
		if err := decodeStrict(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", `body must be {"subject":"...","role":"..."}`)
			return
		}
		tenant := r.Header.Get(TenantHeader)
		var err error
		if grant {
			err = h.auth.Roles.Grant(r.Context(), tenant, who, strings.ToLower(req.Subject), req.Role)
		} else {
			err = h.auth.Roles.Revoke(r.Context(), tenant, who, strings.ToLower(req.Subject), req.Role)
		}
		if err != nil {
			h.fail(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h accessHandlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, access.ErrInvalid):
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", err.Error())
	case errors.Is(err, access.ErrForbidden):
		writeError(w, http.StatusConflict, "forbidden_change", err.Error())
	case errors.Is(err, access.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "binding or tenant not found")
	default:
		logging.FromContext(r.Context()).Error("access request failed", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}
