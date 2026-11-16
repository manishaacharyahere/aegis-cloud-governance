package api

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestRateLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	inv := &fakeInvestigator{}
	h := NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, MaxBodyBytes: 4096,
		Investigator: inv, RateLimit: &RateLimit{PerMinute: 3, ExpensivePerMinute: 2, Now: clock}})
	alice := map[string]string{TenantHeader: "demo", ActorHeader: "alice"}
	bob := map[string]string{TenantHeader: "demo", ActorHeader: "bob"}

	for i := range 3 {
		if rec := do(h, "GET", "/api/v1/investigations/x", nil, alice); rec.Code != 200 {
			t.Fatalf("request %d = %d", i+1, rec.Code)
		}
	}
	rec := do(h, "GET", "/api/v1/investigations/x", nil, alice)
	if rec.Code != 429 || rec.Header().Get("Retry-After") != "20" {
		t.Fatalf("4th request = %d, Retry-After %q (want 429, 20 s for 3/min)", rec.Code, rec.Header().Get("Retry-After"))
	}
	if rec := do(h, "GET", "/api/v1/investigations/x", nil, bob); rec.Code != 200 {
		t.Errorf("another caller must have its own budget: %d", rec.Code)
	}

	// Expensive routes have their own, smaller budget.
	body := func() io.Reader { return strings.NewReader(`{"resource_id":"a"}`) }
	for i := range 2 {
		if rec := do(h, "POST", "/api/v1/investigations", body(), alice); rec.Code != 201 {
			t.Fatalf("expensive request %d = %d", i+1, rec.Code)
		}
	}
	if rec := do(h, "POST", "/api/v1/investigations", body(), alice); rec.Code != 429 {
		t.Errorf("3rd expensive request = %d", rec.Code)
	}

	// Tokens refill over time: one ordinary token every 20 s.
	now = now.Add(21 * time.Second)
	if rec := do(h, "GET", "/api/v1/investigations/x", nil, alice); rec.Code != 200 {
		t.Errorf("after refill = %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/v1/investigations/x", nil, alice); rec.Code != 429 {
		t.Errorf("only one token should have refilled: %d", rec.Code)
	}
	// Anonymous health checks are limited by IP, separately from users.
	if rec := do(h, "GET", "/healthz", nil, nil); rec.Code != 200 {
		t.Errorf("healthz = %d", rec.Code)
	}
}

func TestLimiterBounded(t *testing.T) {
	now := time.Now()
	l := newLimiter(func() time.Time { return now })
	for i := range 1000 {
		l.allow(string(rune(i)), 10)
	}
	now = now.Add(20 * time.Minute)
	l.allow("x", 10)
	if len(l.buckets) != 1 {
		t.Errorf("idle buckets not swept: %d", len(l.buckets))
	}
}
