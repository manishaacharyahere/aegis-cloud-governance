package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/signing"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/audit"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
)

type fakeCompliance struct {
	err        error
	gotScope   string
	gotStale   time.Duration
	gotActor   string
	gotDecided string
}

func (f *fakeCompliance) EvaluateInventory(_ context.Context, _, a string) (compliance.RunSummary, error) {
	f.gotActor = a
	return compliance.RunSummary{RunID: "r"}, f.err
}
func (f *fakeCompliance) EvaluateScan(context.Context, string, string, string) (compliance.RunSummary, error) {
	return compliance.RunSummary{RunID: "r"}, f.err
}
func (f *fakeCompliance) Coverage(_ context.Context, _, _, scope string, stale time.Duration) (compliance.Coverage, error) {
	f.gotScope, f.gotStale = scope, stale
	return compliance.Coverage{}, f.err
}
func (f *fakeCompliance) Control(context.Context, string, string, string, string, time.Duration) (compliance.ControlDetail, error) {
	return compliance.ControlDetail{}, f.err
}
func (f *fakeCompliance) RequestException(_ context.Context, _, a string, _ compliance.ExceptionRequest) (compliance.ExceptionView, error) {
	f.gotActor = a
	return compliance.ExceptionView{ID: "e1"}, f.err
}
func (f *fakeCompliance) DecideException(_ context.Context, _, a, _, d string) (compliance.ExceptionView, error) {
	f.gotActor, f.gotDecided = a, d
	return compliance.ExceptionView{}, f.err
}
func (f *fakeCompliance) ListExceptions(context.Context, string, string, int) ([]compliance.ExceptionView, string, error) {
	return nil, "", f.err
}
func (f *fakeCompliance) AuditEvents(context.Context, string, int, int64) ([]audit.Record, error) {
	return nil, f.err
}
func (f *fakeCompliance) AuditHashAt(_ context.Context, _ string, seq int64) (string, error) {
	if seq == 3 {
		return "h3", nil
	}
	return "", compliance.ErrNotFound
}
func (f *fakeCompliance) VerifyAudit(context.Context, string) (audit.Verification, error) {
	return audit.Verification{Valid: true}, f.err
}

func compHandler(t *testing.T, svc ComplianceService) http.Handler {
	t.Helper()
	cat, err := compliance.LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{},
		Compliance: svc, Catalog: cat, MaxBodyBytes: 4096})
}

var actorHdr = map[string]string{TenantHeader: "demo", ActorHeader: "alice"}

func TestEvaluateRequiresActor(t *testing.T) {
	f := &fakeCompliance{}
	h := compHandler(t, f)
	if rec := do(h, "POST", "/api/v1/compliance/evaluations", strings.NewReader(`{"source":"inventory"}`), tenantHdr); rec.Code != 400 {
		t.Errorf("missing actor = %d", rec.Code)
	}
	rec := do(h, "POST", "/api/v1/compliance/evaluations", strings.NewReader(`{"source":"inventory"}`), actorHdr)
	if rec.Code != 201 || f.gotActor != "alice" {
		t.Errorf("evaluate = %d actor=%q", rec.Code, f.gotActor)
	}
	if rec := do(h, "POST", "/api/v1/compliance/evaluations", strings.NewReader(`{"source":"email"}`), actorHdr); rec.Code != 422 {
		t.Errorf("bad source = %d", rec.Code)
	}
}

func TestCoverageQuery(t *testing.T) {
	f := &fakeCompliance{}
	h := compHandler(t, f)
	if rec := do(h, "GET", "/api/v1/compliance/coverage?framework=nist-csf-2.0&scope=all&stale_after=72h", nil, tenantHdr); rec.Code != 200 {
		t.Fatalf("coverage = %d %s", rec.Code, rec.Body)
	}
	if f.gotScope != "all" || f.gotStale != 72*time.Hour {
		t.Errorf("scope=%q stale=%s", f.gotScope, f.gotStale)
	}
	for _, q := range []string{"", "?framework=x&stale_after=-1h", "?framework=x&stale_after=soon"} {
		if rec := do(h, "GET", "/api/v1/compliance/coverage"+q, nil, tenantHdr); rec.Code != 400 {
			t.Errorf("%q = %d, want 400", q, rec.Code)
		}
	}
}

func TestFrameworksListsCatalogAndNotice(t *testing.T) {
	rec := do(compHandler(t, &fakeCompliance{}), "GET", "/api/v1/compliance/frameworks", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "not certification") || !strings.Contains(rec.Body.String(), "nist-csf-2.0") {
		t.Fatalf("frameworks = %d %s", rec.Code, rec.Body.String()[:200])
	}
}

func TestExceptionDecisionRoutes(t *testing.T) {
	f := &fakeCompliance{}
	h := compHandler(t, f)
	for path, want := range map[string]string{"approve": "approve", "reject": "reject", "revoke": "revoke"} {
		rec := do(h, "POST", "/api/v1/compliance/exceptions/abc/"+path, nil, actorHdr)
		if rec.Code != 200 || f.gotDecided != want {
			t.Errorf("%s = %d decided=%q", path, rec.Code, f.gotDecided)
		}
	}
}

func TestComplianceErrorMapping(t *testing.T) {
	cases := map[error]int{
		compliance.ErrSelfApproval:                      403,
		compliance.ErrConflict:                          409,
		compliance.ErrScanNotReady:                      409,
		fmt.Errorf("%w: bad", compliance.ErrInvalid):    422,
		compliance.ErrNotFound:                          404,
		&opa.UnavailableError{Err: fmt.Errorf("down")}:  503,
		opa.ErrUndefined:                                503,
		fmt.Errorf("db exploded with password=hunter2"): 500,
	}
	for err, want := range cases {
		rec := do(compHandler(t, &fakeCompliance{err: err}), "POST", "/api/v1/compliance/exceptions/abc/approve", nil, actorHdr)
		if rec.Code != want {
			t.Errorf("%v -> %d, want %d", err, rec.Code, want)
		}
		if strings.Contains(rec.Body.String(), "hunter2") {
			t.Error("internal error leaked")
		}
	}
}

func TestActorValidation(t *testing.T) {
	h := compHandler(t, &fakeCompliance{})
	for _, a := range []string{"", "Alice", "a b", strings.Repeat("a", 65), "x\ny"} {
		rec := do(h, "POST", "/api/v1/compliance/exceptions", strings.NewReader(`{}`), map[string]string{TenantHeader: "demo", ActorHeader: a})
		if rec.Code != 400 {
			t.Errorf("actor %q accepted (%d)", a, rec.Code)
		}
	}
}

func TestAuditHeadAndAnchor(t *testing.T) {
	signer := signing.Ephemeral()
	h := NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: fakeDB{}, MaxBodyBytes: 4096,
		Compliance: &fakeCompliance{}, Catalog: mustCatalog(t), Signer: signer})
	rec := do(h, "GET", "/api/v1/audit/head", nil, tenantHdr)
	var head signing.Signed
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &head) != nil || signing.Verify(signer.Public().PublicKey, head) != nil ||
		!strings.Contains(string(head.Payload), `"type":"aegis.audit-head/v1"`) {
		t.Fatalf("head = %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "GET", "/api/v1/signing-key", nil, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), signer.KeyID) {
		t.Errorf("signing key = %d %s", rec.Code, rec.Body)
	}
	for body, want := range map[string]string{`{"seq":3,"hash":"h3"}`: `"matches":true`, `{"seq":3,"hash":"rewritten"}`: `"matches":false`,
		`{"seq":99,"hash":"h3"}`: `"event_exists":false`} {
		if rec := do(h, "POST", "/api/v1/audit/anchors/verify", strings.NewReader(body), tenantHdr); rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("%s -> %d %s", body, rec.Code, rec.Body)
		}
	}
}

func mustCatalog(t *testing.T) *compliance.Catalog {
	t.Helper()
	c, err := compliance.LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return c
}
