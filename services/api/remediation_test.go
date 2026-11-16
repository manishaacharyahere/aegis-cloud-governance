package api

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/remediation"
)

type fakeRemediation struct {
	err        error
	got        remediation.ProposeRequest
	gotAction  string
	gotComment string
}

func (f *fakeRemediation) Propose(_ context.Context, _, _ string, req remediation.ProposeRequest) (remediation.View, error) {
	f.got = req
	return remediation.View{}, f.err
}
func (f *fakeRemediation) Get(context.Context, string, string) (remediation.View, error) {
	return remediation.View{}, f.err
}
func (f *fakeRemediation) List(context.Context, string, string) ([]remediation.View, error) {
	return nil, f.err
}
func (f *fakeRemediation) Decide(_ context.Context, _, _, _, d, c string) (remediation.View, error) {
	f.gotAction, f.gotComment = d, c
	return remediation.View{}, f.err
}
func (f *fakeRemediation) Release(context.Context, string, string, string) (remediation.View, error) {
	f.gotAction = "release"
	return remediation.View{}, f.err
}
func (f *fakeRemediation) Verify(context.Context, string, string, string) (remediation.View, error) {
	f.gotAction = "verify"
	return remediation.View{}, f.err
}

func remHandler(svc RemediationService) http.Handler {
	return NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, Remediation: svc, MaxBodyBytes: 4096})
}

func TestRemediationRoutes(t *testing.T) {
	f := &fakeRemediation{}
	h := remHandler(f)
	body := `{"source":"finding","rule_id":"AEGIS-S3-001","resource_id":"aws_s3_bucket.a","justification":"close the finding"}`
	if rec := do(h, "POST", "/api/v1/remediations", strings.NewReader(body), actorHdr); rec.Code != 201 || f.got.RuleID != "AEGIS-S3-001" {
		t.Errorf("propose = %d %+v", rec.Code, f.got)
	}
	if rec := do(h, "POST", "/api/v1/remediations", strings.NewReader(`{"source":"manual","execute":true}`), actorHdr); rec.Code != 400 {
		t.Errorf("unknown field = %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/v1/remediations/x/approve", strings.NewReader(`{"comment":"ok"}`), actorHdr); rec.Code != 200 || f.gotAction != "approve" || f.gotComment != "ok" {
		t.Errorf("approve = %d %q", rec.Code, f.gotAction)
	}
	for _, step := range []string{"reject", "release", "verify"} {
		if rec := do(h, "POST", "/api/v1/remediations/x/"+step, nil, actorHdr); rec.Code != 200 || f.gotAction != step {
			t.Errorf("%s = %d %q", step, rec.Code, f.gotAction)
		}
	}
	if rec := do(h, "POST", "/api/v1/remediations/x/release", nil, tenantHdr); rec.Code != 400 {
		t.Errorf("release without actor = %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/v1/remediation/templates", nil, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "AEGIS-DB-001") {
		t.Errorf("templates = %d", rec.Code)
	}
}

func TestRemediationErrors(t *testing.T) {
	for err, want := range map[error]int{
		remediation.ErrNotFound:                         404,
		remediation.ErrForbidden:                        403,
		remediation.ErrStale:                            409,
		remediation.ErrNotObserved:                      409,
		fmt.Errorf("%w: x", remediation.ErrConflict):    409,
		fmt.Errorf("%w: x", remediation.ErrInvalid):     422,
		fmt.Errorf("%w (R)", remediation.ErrNoTemplate): 422,
		fmt.Errorf("db: password=hunter2"):              500,
	} {
		rec := do(remHandler(&fakeRemediation{err: err}), "POST", "/api/v1/remediations/x/approve", nil, actorHdr)
		if rec.Code != want || strings.Contains(rec.Body.String(), "hunter2") {
			t.Errorf("%v -> %d", err, rec.Code)
		}
	}
}
