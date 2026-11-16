package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/risk"
)

type fakeRisk struct {
	err      error
	gotW     risk.Weights
	gotBand  string
	gotLimit int
	gotSens  int
	many     bool
}

func (f *fakeRisk) Assess(_ context.Context, _, _ string, w risk.Weights) (risk.Run, error) {
	f.gotW = w
	run := risk.Run{ID: "r"}
	if f.many {
		run.Assessments = make([]risk.Assessment, 50)
	}
	return run, f.err
}
func (f *fakeRisk) GetRun(_ context.Context, _, _, band string, limit int) (risk.Run, error) {
	f.gotBand, f.gotLimit = band, limit
	return risk.Run{}, f.err
}
func (f *fakeRisk) AttackPaths(_ context.Context, _ string, sens, _ int) ([]risk.Path, error) {
	f.gotSens = sens
	return nil, f.err
}

func riskHandler(svc RiskService) http.Handler {
	return NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, Risk: svc, MaxBodyBytes: 4096})
}

func TestRiskAssessDefaultsAndOverrides(t *testing.T) {
	f := &fakeRisk{many: true}
	h := riskHandler(f)
	rec := do(h, "POST", "/api/v1/risk/assessments", nil, actorHdr)
	if rec.Code != 201 || f.gotW != risk.DefaultWeights() || strings.Count(rec.Body.String(), `"rule_id"`) != 20 {
		t.Fatalf("default assess = %d weights=%+v body len=%d", rec.Code, f.gotW, len(rec.Body.String()))
	}
	body := `{"weights":{"severity":0.5,"exposure":0.5,"privilege":0,"criticality":0,"data_sensitivity":0,"age":0}}`
	if rec := do(h, "POST", "/api/v1/risk/assessments", strings.NewReader(body), actorHdr); rec.Code != 201 || f.gotW.Severity != 0.5 {
		t.Errorf("custom weights = %d %+v", rec.Code, f.gotW)
	}
	if rec := do(h, "POST", "/api/v1/risk/assessments", strings.NewReader(`{"weights":{"bogus":1}}`), actorHdr); rec.Code != 400 {
		t.Errorf("unknown weight field = %d", rec.Code)
	}
}

func TestRiskQueries(t *testing.T) {
	f := &fakeRisk{}
	h := riskHandler(f)
	if rec := do(h, "GET", "/api/v1/risk/assessments/x?min_band=high&limit=5", nil, tenantHdr); rec.Code != 200 || f.gotBand != "high" || f.gotLimit != 5 {
		t.Errorf("get run: %d %q %d", rec.Code, f.gotBand, f.gotLimit)
	}
	if rec := do(h, "GET", "/api/v1/risk/attack-paths?min_sensitivity=80", nil, tenantHdr); rec.Code != 200 || f.gotSens != 80 {
		t.Errorf("attack paths: %d %d", rec.Code, f.gotSens)
	}
	for _, q := range []string{"/api/v1/risk/attack-paths?min_sensitivity=101", "/api/v1/risk/attack-paths?limit=0", "/api/v1/risk/assessments/x?limit=abc"} {
		if rec := do(h, "GET", q, nil, tenantHdr); rec.Code != 400 {
			t.Errorf("%s = %d", q, rec.Code)
		}
	}
}

func TestRiskErrors(t *testing.T) {
	for err, want := range map[error]int{
		risk.ErrNoEvaluation:                   409,
		fmt.Errorf("%w: bad", risk.ErrInvalid): 422,
		risk.ErrNotFound:                       404,
		fmt.Errorf("pgx: password=hunter2"):    500,
	} {
		rec := do(riskHandler(&fakeRisk{err: err}), "POST", "/api/v1/risk/assessments", nil, actorHdr)
		if rec.Code != want || strings.Contains(rec.Body.String(), "hunter2") {
			t.Errorf("%v -> %d", err, rec.Code)
		}
	}
}
