package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
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
