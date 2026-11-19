package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/access"
)

// countingVerifier counts how often a token is actually verified.
type countingVerifier struct{ calls atomic.Int32 }

func (c *countingVerifier) Verify(ctx context.Context, raw string) (access.Principal, error) {
	c.calls.Add(1)
	return fakeVerifier{}.Verify(ctx, raw)
}

func TestRejectedTokensAreLimitedPerAddress(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	v := &countingVerifier{}
	lim := &FailedAuthLimit{PerMinute: 3, Now: func() time.Time { return now }}
	h := NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, MaxBodyBytes: 4096,
		Auth: Auth{Mode: AuthOIDC, Verifier: v, Roles: fakeRoles{"demo/viewer@example.com": {"viewer"}}, Failures: lim}})
	call := func(token, ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		req.RemoteAddr = ip + ":40000"
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set(TenantHeader, "demo")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := range 3 {
		if code := call("forged", "203.0.113.7"); code != http.StatusUnauthorized {
			t.Fatalf("rejected token %d = %d, want 401", i, code)
		}
	}
	before := v.calls.Load()
	if code := call("forged", "203.0.113.7"); code != http.StatusTooManyRequests {
		t.Fatalf("4th rejected token = %d, want 429", code)
	}
	if v.calls.Load() != before {
		t.Error("a blocked address still had its token verified")
	}
	if code := call("valid:viewer@example.com", "198.51.100.9"); code != http.StatusOK {
		t.Errorf("another address = %d, want 200", code)
	}
	now = now.Add(time.Minute)
	if code := call("valid:viewer@example.com", "203.0.113.7"); code != http.StatusOK {
		t.Errorf("after the budget refilled = %d, want 200", code)
	}
}

func TestClientIPThroughTrustedProxies(t *testing.T) {
	private := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	cases := []struct {
		name, peer, xff string
		trusted         []netip.Prefix
		want            string
	}{
		{"no proxies trusted: header ignored", "203.0.113.7", "1.2.3.4", nil, "203.0.113.7"},
		{"untrusted peer: header ignored", "203.0.113.7", "1.2.3.4", private, "203.0.113.7"},
		{"web proxy and ingress", "10.1.0.5", "198.51.100.9, 10.2.0.3", private, "198.51.100.9"},
		// A client cannot spoof its address: only the hops added by trusted
		// proxies are skipped, from the right.
		{"spoofed leftmost entry", "10.1.0.5", "6.6.6.6, 198.51.100.9", private, "198.51.100.9"},
		{"only proxies", "10.1.0.5", "10.2.0.3", private, "10.2.0.3"},
	}
	for _, c := range cases {
		f := &FailedAuthLimit{TrustedProxies: c.trusted}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = c.peer + ":1234"
		if c.xff != "" {
			req.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := f.ClientIP(req); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
