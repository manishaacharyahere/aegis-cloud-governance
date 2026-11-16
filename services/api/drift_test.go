package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/drift"
)

type fakeDrift struct {
	err                 error
	gotCat, gotSev, act string
}

func (f *fakeDrift) ApproveBaseline(_ context.Context, _, _, a, _ string) (drift.Baseline, error) {
	f.act = a
	return drift.Baseline{ID: "b"}, f.err
}
func (f *fakeDrift) ListBaselines(context.Context, string) ([]drift.Baseline, error) {
	return nil, f.err
}
func (f *fakeDrift) Compare(_ context.Context, _, _, a string) (drift.Report, error) {
	f.act = a
	return drift.Report{ID: "r"}, f.err
}
func (f *fakeDrift) GetReport(_ context.Context, _, _, c, s string) (drift.Report, error) {
	f.gotCat, f.gotSev = c, s
	return drift.Report{}, f.err
}

func driftHandler(svc DriftService) http.Handler {
	return NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, Drift: svc, MaxBodyBytes: 4096})
}

func TestDriftRoutes(t *testing.T) {
	f := &fakeDrift{}
	h := driftHandler(f)
	if rec := do(h, "POST", "/api/v1/drift/baselines", strings.NewReader(`{"note":"q4"}`), actorHdr); rec.Code != 201 || f.act != "alice" {
		t.Errorf("approve = %d actor=%q", rec.Code, f.act)
	}
	rec := do(h, "POST", "/api/v1/drift/compare", strings.NewReader(`{}`), actorHdr)
	if rec.Code != 201 || rec.Header().Get("Location") != "/api/v1/drift/reports/r" {
		t.Errorf("compare = %d %s", rec.Code, rec.Header())
	}
	if rec := do(h, "GET", "/api/v1/drift/reports/x?category=security&min_severity=high", nil, tenantHdr); rec.Code != 200 ||
		f.gotCat != "security" || f.gotSev != "high" {
		t.Errorf("report filters: %d %q %q", rec.Code, f.gotCat, f.gotSev)
	}
	if rec := do(h, "POST", "/api/v1/drift/compare", strings.NewReader(`{}`), tenantHdr); rec.Code != 400 {
		t.Errorf("compare without actor = %d", rec.Code)
	}
}

func TestDriftErrorMapping(t *testing.T) {
	for err, want := range map[error]int{
		drift.ErrNoBaseline:          409,
		drift.ErrNoInventory:         409,
		drift.ErrAmbiguous:           422,
		drift.ErrNotFound:            404,
		errors.New("secret=hunter2"): 500,
	} {
		rec := do(driftHandler(&fakeDrift{err: err}), "POST", "/api/v1/drift/compare", strings.NewReader(`{}`), actorHdr)
		if rec.Code != want || strings.Contains(rec.Body.String(), "hunter2") {
			t.Errorf("%v -> %d %s, want %d", err, rec.Code, rec.Body, want)
		}
	}
}
