package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/investigator"
)

type fakeInvestigator struct {
	err   error
	got   investigator.Request
	gotID string
}

func (f *fakeInvestigator) Status() map[string]any { return map[string]any{"mode": "deterministic"} }
func (f *fakeInvestigator) Investigate(_ context.Context, _, _ string, req investigator.Request) (investigator.Investigation, error) {
	f.got = req
	return investigator.Investigation{ID: "x"}, f.err
}
func (f *fakeInvestigator) Get(_ context.Context, _, id string) (investigator.Investigation, error) {
	f.gotID = id
	return investigator.Investigation{ID: id}, f.err
}

func igHandler(svc InvestigatorService) http.Handler {
	return NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, Investigator: svc, MaxBodyBytes: 4096})
}

func TestInvestigationRoutes(t *testing.T) {
	f := &fakeInvestigator{}
	h := igHandler(f)
	body := `{"resource_id":"aws_s3_bucket.a","question":"why?"}`
	if rec := do(h, "POST", "/api/v1/investigations", strings.NewReader(body), actorHdr); rec.Code != 201 || f.got.ResourceID != "aws_s3_bucket.a" || f.got.Question != "why?" {
		t.Errorf("create = %d %+v", rec.Code, f.got)
	}
	if rec := do(h, "POST", "/api/v1/investigations", strings.NewReader(`{"resource_id":"a","tools":["shell"]}`), actorHdr); rec.Code != 400 {
		t.Errorf("unknown field = %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/v1/investigations", strings.NewReader(body), tenantHdr); rec.Code != 400 {
		t.Errorf("missing actor = %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/v1/investigations/abc", nil, tenantHdr); rec.Code != 200 || f.gotID != "abc" {
		t.Errorf("get = %d %q", rec.Code, f.gotID)
	}
	if rec := do(h, "GET", "/api/v1/assistant/status", nil, tenantHdr); rec.Code != 200 || !strings.Contains(rec.Body.String(), "deterministic") {
		t.Errorf("status = %d %s", rec.Code, rec.Body)
	}
	if rec := do(igHandler(nil), "GET", "/api/v1/assistant/status", nil, tenantHdr); rec.Code != 503 {
		t.Errorf("unconfigured = %d", rec.Code)
	}
}

func TestInvestigationErrors(t *testing.T) {
	for err, want := range map[error]int{
		investigator.ErrNotFound:                            404,
		investigator.ErrTenantNotFound:                      404,
		investigator.ErrAmbiguous:                           409,
		fmt.Errorf("%w: too long", investigator.ErrInvalid): 422,
		fmt.Errorf("db: password=hunter2"):                  500,
	} {
		rec := do(igHandler(&fakeInvestigator{err: err}), "POST", "/api/v1/investigations", strings.NewReader(`{"resource_id":"a"}`), actorHdr)
		if rec.Code != want || strings.Contains(rec.Body.String(), "hunter2") {
			t.Errorf("%v -> %d", err, rec.Code)
		}
	}
}
