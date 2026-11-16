package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/finops"
)

type fakeFinOps struct {
	err                  error
	gotRaw, gotGroup     string
	gotAction, gotImplAt string
	gotKind, gotEntity   string
	dup                  bool
}

func (f *fakeFinOps) Import(_ context.Context, _, _ string, raw []byte) (finops.ImportResult, error) {
	f.gotRaw = string(raw)
	return finops.ImportResult{Duplicate: f.dup}, f.err
}
func (f *fakeFinOps) Summarize(_ context.Context, _, gb, _, _ string) (finops.Summary, error) {
	f.gotGroup = gb
	return finops.Summary{}, f.err
}
func (f *fakeFinOps) TagCoverage(context.Context, string) (map[string]any, error) { return nil, f.err }
func (f *fakeFinOps) GenerateRecommendations(context.Context, string, string, string) ([]finops.RecView, error) {
	return nil, f.err
}
func (f *fakeFinOps) ListRecommendations(context.Context, string, string) ([]finops.RecView, error) {
	return nil, f.err
}
func (f *fakeFinOps) DecideRecommendation(_ context.Context, _, _, _, action, impl string) (finops.RecView, error) {
	f.gotAction, f.gotImplAt = action, impl
	return finops.RecView{}, f.err
}
func (f *fakeFinOps) LatestML(_ context.Context, _, kind, entity string) (finops.MLResult, error) {
	f.gotKind, f.gotEntity = kind, entity
	return finops.MLResult{}, f.err
}

func finHandler(svc FinOpsService) http.Handler {
	return NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, FinOps: svc,
		MaxBodyBytes: 4096, MaxImportBytes: 8192})
}

func TestCostImport(t *testing.T) {
	f := &fakeFinOps{}
	h := finHandler(f)
	if rec := do(h, "POST", "/api/v1/cost/import", strings.NewReader("a,b\n1,2\n"), actorHdr); rec.Code != 201 || f.gotRaw != "a,b\n1,2\n" {
		t.Fatalf("import = %d raw=%q", rec.Code, f.gotRaw)
	}
	f.dup = true
	if rec := do(h, "POST", "/api/v1/cost/import", strings.NewReader("x"), actorHdr); rec.Code != 200 {
		t.Errorf("duplicate = %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/v1/cost/import", strings.NewReader(strings.Repeat("a", 9000)), actorHdr); rec.Code != 413 {
		t.Errorf("oversized = %d", rec.Code)
	}
	verr := &finops.ValidationError{Errors: []finops.RowError{{Line: 3, Column: "cost_usd", Message: "must be a number"}}}
	rec := do(finHandler(&fakeFinOps{err: verr}), "POST", "/api/v1/cost/import", strings.NewReader("x"), actorHdr)
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), `"cost_usd"`) {
		t.Errorf("validation = %d %s", rec.Code, rec.Body)
	}
}

func TestFinOpsRoutes(t *testing.T) {
	f := &fakeFinOps{}
	h := finHandler(f)
	if rec := do(h, "GET", "/api/v1/cost/summary", nil, tenantHdr); rec.Code != 200 || f.gotGroup != "team" {
		t.Errorf("summary default group = %d %q", rec.Code, f.gotGroup)
	}
	if rec := do(h, "POST", "/api/v1/recommendations/abc/implement", strings.NewReader(`{"implemented_at":"2025-06-01"}`), actorHdr); rec.Code != 200 ||
		f.gotAction != "implement" || f.gotImplAt != "2025-06-01" {
		t.Errorf("implement = %d %q %q", rec.Code, f.gotAction, f.gotImplAt)
	}
	if rec := do(h, "GET", "/api/v1/cost/forecast?entity=payments", nil, tenantHdr); rec.Code != 200 || f.gotKind != "forecast" || f.gotEntity != "payments" {
		t.Errorf("forecast = %d %q %q", rec.Code, f.gotKind, f.gotEntity)
	}
	if rec := do(h, "GET", "/api/v1/cost/anomalies", nil, tenantHdr); rec.Code != 200 || f.gotKind != "anomaly" {
		t.Errorf("anomalies = %d %q", rec.Code, f.gotKind)
	}
}

func TestFinOpsErrors(t *testing.T) {
	for err, want := range map[error]int{
		finops.ErrNoData:                         404,
		finops.ErrConflict:                       409,
		fmt.Errorf("%w: bad", finops.ErrInvalid): 422,
		fmt.Errorf("db: password=hunter2"):       500,
	} {
		rec := do(finHandler(&fakeFinOps{err: err}), "GET", "/api/v1/cost/summary", nil, tenantHdr)
		if rec.Code != want || strings.Contains(rec.Body.String(), "hunter2") {
			t.Errorf("%v -> %d", err, rec.Code)
		}
	}
}
