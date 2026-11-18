package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/access"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/remediation"
)

type fakeVerifier struct{ down bool }

func (f fakeVerifier) Verify(_ context.Context, raw string) (access.Principal, error) {
	if f.down {
		return access.Principal{}, access.ErrProviderUnavailable
	}
	if s, ok := strings.CutPrefix(raw, "valid:"); ok {
		return access.Principal{Subject: s, Method: AuthOIDC}, nil
	}
	return access.Principal{}, access.ErrUnauthenticated
}

type fakeRoles map[string][]string // "tenant/subject" -> roles

func (f fakeRoles) RolesFor(_ context.Context, tenant, subject string) ([]string, error) {
	return f[tenant+"/"+subject], nil
}
func (f fakeRoles) List(context.Context, string) ([]access.Binding, error) { return nil, nil }
func (f fakeRoles) Grant(context.Context, string, string, string, string) error {
	return nil
}
func (f fakeRoles) Revoke(context.Context, string, string, string, string) error {
	return errors.New("unused")
}
func (f fakeRoles) Memberships(_ context.Context, subject string, all bool) ([]access.Membership, error) {
	var out []access.Membership
	for k, roles := range f {
		tenant, sub, _ := strings.Cut(k, "/")
		if all || sub == subject {
			out = append(out, access.Membership{Slug: tenant, Name: tenant, Roles: roles})
		}
	}
	return out, nil
}

func TestMeTenants(t *testing.T) {
	h := oidcHandler(fakeVerifierForTenants{}, &fakeInvestigator{}, &fakeRemediation{})
	rec := do(h, "GET", "/api/v1/me/tenants", nil, map[string]string{"Authorization": "Bearer valid:approver@example.com"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"roles":["approver"]`) ||
		strings.Contains(rec.Body.String(), "admin") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "GET", "/api/v1/me/tenants", nil, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rec.Code)
	}
}

type fakeVerifierForTenants struct{}

func (fakeVerifierForTenants) Verify(_ context.Context, raw string) (access.Principal, error) {
	if s, ok := strings.CutPrefix(raw, "valid:"); ok {
		return access.Principal{Subject: s, Method: AuthOIDC}, nil
	}
	return access.Principal{}, access.ErrUnauthenticated
}

func oidcHandler(v TokenVerifier, inv *fakeInvestigator, rem *fakeRemediation) http.Handler {
	roles := fakeRoles{
		"demo/viewer@example.com":   {"viewer"},
		"demo/analyst@example.com":  {"analyst"},
		"demo/approver@example.com": {"approver"},
		"demo/admin@example.com":    {"admin"},
	}
	return NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, MaxBodyBytes: 4096,
		Investigator: inv, Remediation: rem, Auth: Auth{Mode: AuthOIDC, Verifier: v, Roles: roles}})
}

func bearer(subject string, extra map[string]string) map[string]string {
	h := map[string]string{"Authorization": "Bearer valid:" + subject, TenantHeader: "demo"}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

func TestOIDCAuthorization(t *testing.T) {
	inv, rem := &fakeInvestigator{}, &fakeRemediation{}
	h := oidcHandler(fakeVerifier{}, inv, rem)
	body := func() io.Reader { return strings.NewReader(`{"resource_id":"aws_s3_bucket.a"}`) }

	if rec := do(h, "GET", "/api/v1/version", nil, nil); rec.Code != 200 {
		t.Errorf("public route = %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/v1/investigations/x", nil, map[string]string{TenantHeader: "demo"}); rec.Code != 401 ||
		rec.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("no token = %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/v1/investigations/x", nil, map[string]string{"Authorization": "Bearer forged", TenantHeader: "demo"}); rec.Code != 401 {
		t.Errorf("invalid token = %d", rec.Code)
	}
	// The dev actor header grants nothing in OIDC mode.
	if rec := do(h, "GET", "/api/v1/investigations/x", nil, map[string]string{ActorHeader: "admin@example.com", TenantHeader: "demo"}); rec.Code != 401 {
		t.Errorf("actor header without token = %d", rec.Code)
	}
	if rec := do(oidcHandler(fakeVerifier{down: true}, inv, rem), "GET", "/api/v1/investigations/x", nil, bearer("viewer@example.com", nil)); rec.Code != 503 {
		t.Errorf("provider down = %d", rec.Code)
	}

	for _, tc := range []struct {
		who, method, path string
		want              int
	}{
		{"viewer@example.com", "GET", "/api/v1/investigations/x", 200},
		{"viewer@example.com", "POST", "/api/v1/investigations", 403},
		{"analyst@example.com", "POST", "/api/v1/investigations", 201},
		{"analyst@example.com", "POST", "/api/v1/remediations/x/approve", 403},
		{"approver@example.com", "POST", "/api/v1/remediations/x/approve", 200},
		{"approver@example.com", "POST", "/api/v1/investigations", 403},
		{"stranger@example.com", "GET", "/api/v1/investigations/x", 403},
		{"analyst@example.com", "GET", "/api/v1/access/bindings", 403},
		{"admin@example.com", "GET", "/api/v1/access/bindings", 200},
	} {
		var b io.Reader
		if tc.method == "POST" {
			b = body()
			if strings.HasSuffix(tc.path, "/approve") {
				b = nil
			}
		}
		if rec := do(h, tc.method, tc.path, b, bearer(tc.who, nil)); rec.Code != tc.want {
			t.Errorf("%s %s %s = %d, want %d (%s)", tc.who, tc.method, tc.path, rec.Code, tc.want, rec.Body)
		}
	}
	// Another tenant: no roles there, same 403 as an unknown tenant.
	if rec := do(h, "GET", "/api/v1/investigations/x", nil, bearer("admin@example.com", map[string]string{TenantHeader: "other"})); rec.Code != 403 {
		t.Errorf("other tenant = %d", rec.Code)
	}

	rec := do(h, "GET", "/api/v1/me", nil, bearer("analyst@example.com", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"roles":["analyst"]`) || !strings.Contains(rec.Body.String(), `"subject":"analyst@example.com"`) {
		t.Errorf("me = %d %s", rec.Code, rec.Body)
	}
}

type actorCapture struct {
	fakeRemediation
	actor string
}

func (a *actorCapture) Decide(_ context.Context, _, actor, _, d, _ string) (remediation.View, error) {
	a.actor = actor
	return remediation.View{}, nil
}

func TestOIDCActorIsTokenSubject(t *testing.T) {
	rem := &actorCapture{}
	h := NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, MaxBodyBytes: 4096, Remediation: rem,
		Auth: Auth{Mode: AuthOIDC, Verifier: fakeVerifier{}, Roles: fakeRoles{"demo/bob@example.com": {"approver"}}}})
	do(h, "POST", "/api/v1/remediations/x/approve", nil, bearer("bob@example.com", map[string]string{ActorHeader: "alice@example.com"}))
	if rem.actor != "bob@example.com" {
		t.Errorf("actor = %q, want the token subject", rem.actor)
	}
}

// Every permission entry must belong to a registered route (no stale or
// misspelled entries), and NewHandler panics if a route has no entry.
func TestRoutePermissionsTable(t *testing.T) {
	h := NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, MaxBodyBytes: 4096})
	for pattern := range routePermissions {
		method, path, _ := strings.Cut(pattern, " ")
		path = strings.NewReplacer("{id}", "x", "{framework}", "x", "{control}", "x").Replace(path)
		if rec := do(h, method, path, nil, map[string]string{TenantHeader: "demo"}); rec.Code == 404 && !strings.Contains(rec.Body.String(), "not_found") ||
			rec.Code == 405 {
			t.Errorf("%s: no such route (%d)", pattern, rec.Code)
		}
	}
}

// Development mode accepts only loopback peers that address the API by a
// local name (no LAN peers unless trusted, no DNS-rebound hosts).
func TestDevModeLocalOnly(t *testing.T) {
	h := NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, MaxBodyBytes: 4096})
	trusted := NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, MaxBodyBytes: 4096,
		Auth: Auth{Mode: AuthDevHeaders, DevTrustPrivateNetwork: true}})
	for _, tc := range []struct {
		name, remote, host string
		h                  http.Handler
		want               int
	}{
		{"loopback, localhost", "127.0.0.1:1", "localhost:8080", h, http.StatusOK},
		{"loopback, 127.0.0.1", "127.0.0.1:1", "127.0.0.1:8080", h, http.StatusOK},
		{"ipv6 loopback", "[::1]:1", "[::1]:8080", h, http.StatusOK},
		{"LAN peer", "192.168.1.20:1", "localhost:8080", h, http.StatusForbidden},
		{"LAN peer, trusted private network", "172.18.0.1:1", "localhost:8080", trusted, http.StatusOK},
		{"public peer even when private is trusted", "203.0.113.9:1", "localhost:8080", trusted, http.StatusForbidden},
		{"DNS rebinding", "127.0.0.1:1", "evil.example:8080", h, http.StatusForbidden},
	} {
		req := httptest.NewRequest("GET", "/api/v1/me", nil)
		req.RemoteAddr, req.Host = tc.remote, tc.host
		req.Header.Set("X-Aegis-Actor", "dev@example.com")
		rec := httptest.NewRecorder()
		tc.h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, rec.Code, tc.want)
		}
	}
}
