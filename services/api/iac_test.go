package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/iac"
)

type fakeIaC struct {
	created bool
	gotRef  string
	gotKey  string
	getErr  error
}

func (f *fakeIaC) Enqueue(_ context.Context, _, ref, key string) (iac.Scan, bool, error) {
	f.gotRef, f.gotKey = ref, key
	return iac.Scan{ID: "s1", Status: iac.StatusQueued}, f.created, nil
}
func (f *fakeIaC) Get(context.Context, string, string) (iac.Report, error) {
	return iac.Report{}, f.getErr
}
func (f *fakeIaC) List(_ context.Context, _, after string, _ int) ([]iac.Scan, string, error) {
	if after == "bad" {
		return nil, "", iac.ErrInvalidCursor
	}
	return []iac.Scan{{ID: "s1"}}, "next", nil
}

func TestListScansAndFixtures(t *testing.T) {
	h := NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, IaC: &fakeIaC{},
		MaxBodyBytes: 1024, Fixtures: []string{"iam-wildcard", "secure-baseline"}})
	rec := do(h, http.MethodGet, "/api/v1/iac/scans?limit=5", nil, map[string]string{TenantHeader: "demo"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"next_cursor":"next"`) {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, http.MethodGet, "/api/v1/iac/scans?after=bad", nil, map[string]string{TenantHeader: "demo"}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad cursor: %d", rec.Code)
	}
	rec = do(h, http.MethodGet, "/api/v1/iac/fixtures", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `["iam-wildcard","secure-baseline"]`) {
		t.Fatalf("fixtures: %d %s", rec.Code, rec.Body)
	}
}

func iacHandler(svc IaCService) http.Handler {
	return NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, IaC: svc, MaxBodyBytes: 1024})
}

const scanBody = `{"source":{"type":"fixture","ref":"insecure-storage"}}`

func TestCreateScan(t *testing.T) {
	f := &fakeIaC{created: true}
	rec := do(iacHandler(f), http.MethodPost, "/api/v1/iac/scans", strings.NewReader(scanBody),
		map[string]string{TenantHeader: "demo", "Idempotency-Key": "ci-run-42"})
	if rec.Code != http.StatusAccepted || rec.Header().Get("Location") != "/api/v1/iac/scans/s1" {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if f.gotRef != "insecure-storage" || f.gotKey != "ci-run-42" {
		t.Errorf("passed ref=%q key=%q", f.gotRef, f.gotKey)
	}

	f.created = false
	if rec := do(iacHandler(f), http.MethodPost, "/api/v1/iac/scans", strings.NewReader(scanBody), tenantHdr); rec.Code != http.StatusOK {
		t.Errorf("idempotent replay = %d, want 200", rec.Code)
	}
}

func TestCreateScanRejectsBadInput(t *testing.T) {
	cases := []struct {
		body string
		hdr  map[string]string
		code int
	}{
		{scanBody, nil, 400},
		{`{"source":{"type":"git","ref":"x"}}`, tenantHdr, 422},
		{`{"source":{"type":"fixture","ref":"../../etc"}}`, tenantHdr, 422},
		{`{"source":{"type":"fixture","ref":"x"},"extra":1}`, tenantHdr, 400},
		{scanBody, map[string]string{TenantHeader: "demo", "Idempotency-Key": "bad key with spaces"}, 400},
	}
	for _, c := range cases {
		if rec := do(iacHandler(&fakeIaC{}), http.MethodPost, "/api/v1/iac/scans", strings.NewReader(c.body), c.hdr); rec.Code != c.code {
			t.Errorf("%s %v -> %d, want %d (%s)", c.body, c.hdr, rec.Code, c.code, rec.Body)
		}
	}
}

func TestGetScanNotFoundAndUnconfigured(t *testing.T) {
	if rec := do(iacHandler(&fakeIaC{getErr: iac.ErrNotFound}), http.MethodGet, "/api/v1/iac/scans/x", nil, tenantHdr); rec.Code != 404 {
		t.Errorf("not found = %d", rec.Code)
	}
	if rec := do(iacHandler(nil), http.MethodGet, "/api/v1/iac/scans/x", nil, tenantHdr); rec.Code != 503 {
		t.Errorf("unconfigured = %d", rec.Code)
	}
}
