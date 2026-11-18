package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/signing"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/api"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
)

// The signed audit head must verify against the real chain: this path was
// only ever tested through a fake, which hid a bytea-to-string scan error.
func TestAuditAnchorRoundTrip(t *testing.T) {
	pool, _ := migratedPool(t)
	ctx := context.Background()
	var tenantID string
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = 'demo'`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			return audit.Append(ctx, tx, tenantID, audit.Event{Actor: "alice@example.com", Action: "test.event",
				TargetType: "test", TargetID: fmt.Sprint(i), Outcome: "success"})
		}); err != nil {
			t.Fatal(err)
		}
	}
	cat, _ := compliance.LoadCatalog()
	h := api.NewHandler(api.Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: pool, MaxBodyBytes: 4096,
		Compliance: &compliance.Service{Pool: pool, Catalog: cat}, Catalog: cat, Signer: signing.Ephemeral()})
	call := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr, req.Host = "127.0.0.1:1", "localhost"
		req.Header.Set("X-Aegis-Tenant", "demo")
		req.Header.Set("X-Aegis-Actor", "alice@example.com")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := call(http.MethodGet, "/api/v1/audit/head", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("head: %d %s", rec.Code, rec.Body)
	}
	var signed struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &signed); err != nil || len(signed.Payload) == 0 {
		t.Fatalf("head response: %s", rec.Body)
	}
	var head struct {
		Seq  int64  `json:"seq"`
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(signed.Payload, &head); err != nil || head.Seq != 3 || len(head.Hash) != 64 {
		t.Fatalf("head payload: %s", signed.Payload)
	}

	for name, tc := range map[string]struct {
		hash  string
		match bool
	}{
		"exact":     {head.Hash, true},
		"uppercase": {strings.ToUpper(head.Hash), true},
		"tampered":  {strings.Repeat("0", 64), false},
	} {
		rec = call(http.MethodPost, "/api/v1/audit/anchors/verify", fmt.Sprintf(`{"seq": %d, "hash": %q}`, head.Seq, tc.hash))
		var out struct {
			Matches bool `json:"matches"`
			Intact  bool `json:"anchored_and_intact"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Matches != tc.match || out.Intact != tc.match {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}
