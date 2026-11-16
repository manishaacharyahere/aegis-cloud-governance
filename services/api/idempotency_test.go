package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/investigator"
)

type memIdem struct {
	mu   sync.Mutex
	recs map[string]*IdemRecord
}

func (m *memIdem) Begin(_ context.Context, k IdemKey) (*IdemRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := k.Tenant + "|" + k.Actor + "|" + k.Key
	if r, ok := m.recs[id]; ok {
		c := *r
		return &c, nil
	}
	m.recs[id] = &IdemRecord{Route: k.Route, RequestSHA: k.RequestSHA}
	return nil, nil
}
func (m *memIdem) Complete(_ context.Context, k IdemKey, status int, ct string, body []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.recs[k.Tenant+"|"+k.Actor+"|"+k.Key]
	r.Status, r.ContentType, r.Body = status, ct, append([]byte(nil), body...)
	return nil
}
func (m *memIdem) Abort(_ context.Context, k IdemKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.recs, k.Tenant+"|"+k.Actor+"|"+k.Key)
	return nil
}

type countingInvestigator struct {
	fakeInvestigator
	calls int
	fail  bool
}

func (c *countingInvestigator) Investigate(ctx context.Context, t, a string, req investigator.Request) (investigator.Investigation, error) {
	c.calls++
	if c.fail {
		return investigator.Investigation{}, context.DeadlineExceeded // maps to 500
	}
	return investigator.Investigation{ID: "inv-1"}, nil
}

func TestIdempotencyKey(t *testing.T) {
	inv := &countingInvestigator{}
	store := &memIdem{recs: map[string]*IdemRecord{}}
	h := NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, MaxBodyBytes: 4096,
		Investigator: inv, Idempotency: store})
	hdr := map[string]string{TenantHeader: "demo", ActorHeader: "alice", IdempotencyHeader: "retry-1"}
	body := func(s string) io.Reader { return strings.NewReader(s) }

	first := do(h, "POST", "/api/v1/investigations", body(`{"resource_id":"a"}`), hdr)
	again := do(h, "POST", "/api/v1/investigations", body(`{"resource_id":"a"}`), hdr)
	if first.Code != 201 || again.Code != 201 || inv.calls != 1 || again.Header().Get("Idempotent-Replayed") != "true" ||
		again.Body.String() != first.Body.String() {
		t.Fatalf("replay: %d/%d calls=%d replayed=%q", first.Code, again.Code, inv.calls, again.Header().Get("Idempotent-Replayed"))
	}
	if rec := do(h, "POST", "/api/v1/investigations", body(`{"resource_id":"b"}`), hdr); rec.Code != 422 || inv.calls != 1 {
		t.Errorf("same key, different body = %d", rec.Code)
	}
	// Keys are per caller: bob's identical key is a new request.
	bob := map[string]string{TenantHeader: "demo", ActorHeader: "bob", IdempotencyHeader: "retry-1"}
	if rec := do(h, "POST", "/api/v1/investigations", body(`{"resource_id":"a"}`), bob); rec.Code != 201 || inv.calls != 2 {
		t.Errorf("other caller = %d calls=%d", rec.Code, inv.calls)
	}
	// A request still in progress is not run twice.
	sum := sha256.Sum256([]byte("/api/v1/investigations\n" + `{"resource_id":"a"}`))
	store.recs["demo|alice|busy"] = &IdemRecord{Route: "POST /api/v1/investigations", RequestSHA: hex.EncodeToString(sum[:])}
	busy := map[string]string{TenantHeader: "demo", ActorHeader: "alice", IdempotencyHeader: "busy"}
	if rec := do(h, "POST", "/api/v1/investigations", body(`{"resource_id":"a"}`), busy); rec.Code != 409 {
		t.Errorf("in progress = %d", rec.Code)
	}
	// Server errors are not stored: the retry runs again.
	inv.fail = true
	fh := map[string]string{TenantHeader: "demo", ActorHeader: "alice", IdempotencyHeader: "flaky"}
	do(h, "POST", "/api/v1/investigations", body(`{"resource_id":"a"}`), fh)
	inv.fail = false
	before := inv.calls
	if rec := do(h, "POST", "/api/v1/investigations", body(`{"resource_id":"a"}`), fh); rec.Code != 201 || inv.calls != before+1 {
		t.Errorf("retry after 5xx = %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/v1/investigations", body(`{"resource_id":"a"}`), map[string]string{TenantHeader: "demo", ActorHeader: "alice", IdempotencyHeader: "bad key!"}); rec.Code != 400 {
		t.Errorf("invalid key = %d", rec.Code)
	}
	// No header: unchanged behaviour.
	before = inv.calls
	do(h, "POST", "/api/v1/investigations", body(`{"resource_id":"a"}`), map[string]string{TenantHeader: "demo", ActorHeader: "alice"})
	do(h, "POST", "/api/v1/investigations", body(`{"resource_id":"a"}`), map[string]string{TenantHeader: "demo", ActorHeader: "alice"})
	if inv.calls != before+2 {
		t.Error("requests without a key must not be de-duplicated")
	}
}
