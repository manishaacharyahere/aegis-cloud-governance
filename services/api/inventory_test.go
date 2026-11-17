package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
)

type fakeInventory struct {
	importErr error
	report    inventory.ImportReport
	lastSnap  inventory.Snapshot
	lastF     inventory.ListFilter
	getErr    error
}

func (f *fakeInventory) Import(_ context.Context, _ string, s inventory.Snapshot) (inventory.ImportReport, error) {
	f.lastSnap = s
	return f.report, f.importErr
}
func (f *fakeInventory) GetImport(context.Context, string, string) (inventory.ImportReport, error) {
	return f.report, f.getErr
}
func (f *fakeInventory) ListResources(_ context.Context, _ string, lf inventory.ListFilter) (inventory.ResourcePage, error) {
	f.lastF = lf
	return inventory.ResourcePage{Items: []inventory.ResourceView{}}, nil
}
func (f *fakeInventory) GetResource(context.Context, string, string) (inventory.ResourceDetail, error) {
	return inventory.ResourceDetail{}, f.getErr
}
func (f *fakeInventory) ResourceTypes(context.Context, string) ([]inventory.TypeCount, error) {
	return []inventory.TypeCount{{ResourceType: "aws_s3_bucket", Count: 3}}, nil
}

func TestResourceTypes(t *testing.T) {
	rec := do(invHandler(&fakeInventory{}), http.MethodGet, "/api/v1/resources/types", nil, map[string]string{TenantHeader: "demo"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `{"resource_type":"aws_s3_bucket","count":3}`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestImportTerraformState(t *testing.T) {
	f := &fakeInventory{report: inventory.ImportReport{ImportID: "i1"}}
	state := `{"version":4,"resources":[{"mode":"managed","type":"aws_kms_key","name":"k",
		"provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
		"instances":[{"attributes":{"arn":"arn:aws:kms:eu-west-1:123456789012:key/k","enable_key_rotation":true}}]}]}`
	rec := do(invHandler(f), http.MethodPost, "/api/v1/inventory/import/terraform-state?environment=production",
		strings.NewReader(state), map[string]string{TenantHeader: "demo"})
	if rec.Code != http.StatusCreated || rec.Header().Get("Location") != "/api/v1/inventory/imports/i1" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if f.lastSnap.Source != "terraform_state" || len(f.lastSnap.Resources) != 1 || f.lastSnap.Resources[0].Environment != "production" {
		t.Errorf("snapshot passed on: %+v", f.lastSnap)
	}
	rec = do(invHandler(f), http.MethodPost, "/api/v1/inventory/import/terraform-state", strings.NewReader(`{"version":3}`),
		map[string]string{TenantHeader: "demo"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_state") {
		t.Errorf("old state version: %d %s", rec.Code, rec.Body)
	}
}

func invHandler(svc InventoryService) http.Handler {
	return NewHandler(Deps{
		Logger:         slog.New(slog.NewJSONHandler(io.Discard, nil)),
		DB:             fakeDB{},
		Inventory:      svc,
		MaxBodyBytes:   1024,
		MaxImportBytes: 4096,
	})
}

const validBody = `{"schema_version":"aegis.inventory/v1","source":"synthetic","captured_at":"2026-01-01T00:00:00Z",
 "account":{"provider":"aws","external_id":"123456789012","name":"demo"},
 "resources":[{"resource_id":"aws_s3_bucket.a","resource_type":"aws_s3_bucket","configuration":{"port":22}}]}`

var tenantHdr = map[string]string{TenantHeader: "demo"}

func TestImportCreatedAndReplay(t *testing.T) {
	f := &fakeInventory{report: inventory.ImportReport{ImportSummary: inventory.ImportSummary{ImportID: "abc"}}}
	h := invHandler(f)

	rec := do(h, http.MethodPost, "/api/v1/inventory/import", strings.NewReader(validBody), tenantHdr)
	if rec.Code != http.StatusCreated || rec.Header().Get("Location") != "/api/v1/inventory/imports/abc" {
		t.Fatalf("first import = %d %s", rec.Code, rec.Body)
	}
	if _, isNumber := f.lastSnap.Resources[0].Configuration["port"].(json.Number); !isNumber {
		t.Error("numbers should be decoded as json.Number to preserve precision")
	}

	f.report.Duplicate = true
	if rec := do(h, http.MethodPost, "/api/v1/inventory/import", strings.NewReader(validBody), tenantHdr); rec.Code != http.StatusOK {
		t.Fatalf("replay = %d, want 200", rec.Code)
	}
}

func TestImportRequestErrors(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		hdr    map[string]string
		err    error
		status int
		code   string
	}{
		{"no tenant", validBody, nil, nil, 400, "invalid_tenant"},
		{"bad tenant", validBody, map[string]string{TenantHeader: "../etc"}, nil, 400, "invalid_tenant"},
		{"bad json", `{"schema_version":`, tenantHdr, nil, 400, "invalid_json"},
		{"unknown field", `{"surprise":1}`, tenantHdr, nil, 400, "invalid_json"},
		{"two documents", validBody + validBody, tenantHdr, nil, 400, "invalid_json"},
		{"too large", `{"x":"` + strings.Repeat("a", 5000) + `"}`, tenantHdr, nil, 413, "body_too_large"},
		{"validation", validBody, tenantHdr, &inventory.ValidationError{Issues: []inventory.Issue{{Path: "source", Message: "bad"}}}, 422, "validation_failed"},
		{"stale", validBody, tenantHdr, fmt.Errorf("wrap: %w", inventory.ErrStaleSnapshot), 409, "stale_snapshot"},
		{"tenant missing", validBody, tenantHdr, inventory.ErrTenantNotFound, 404, "tenant_not_found"},
		{"internal", validBody, tenantHdr, errors.New("pq: password=hunter2 failed"), 500, "internal_error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(invHandler(&fakeInventory{importErr: tt.err}), http.MethodPost, "/api/v1/inventory/import",
				strings.NewReader(tt.body), tt.hdr)
			if rec.Code != tt.status || !strings.Contains(rec.Body.String(), `"`+tt.code+`"`) {
				t.Fatalf("got %d %s, want %d %s", rec.Code, rec.Body, tt.status, tt.code)
			}
			if strings.Contains(rec.Body.String(), "hunter2") {
				t.Error("internal error details leaked")
			}
		})
	}
}

func TestValidationIssuesReturned(t *testing.T) {
	f := &fakeInventory{importErr: &inventory.ValidationError{Issues: []inventory.Issue{{Path: "account.external_id", Message: "must be 12 digits"}}}}
	rec := do(invHandler(f), http.MethodPost, "/api/v1/inventory/import", strings.NewReader(validBody), tenantHdr)
	var body validationErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body.Error.Issues) != 1 || body.Error.Issues[0].Path != "account.external_id" {
		t.Fatalf("issues not returned: %s", rec.Body)
	}
}

func TestListResourcesQueryParsing(t *testing.T) {
	f := &fakeInventory{}
	h := invHandler(f)
	rec := do(h, http.MethodGet, "/api/v1/resources?type=storage.bucket&environment=production&include_deleted=true&limit=5", nil, tenantHdr)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	if f.lastF.ResourceType != "storage.bucket" || f.lastF.Environment != "production" || !f.lastF.IncludeDeleted || f.lastF.Limit != 5 {
		t.Errorf("filter = %+v", f.lastF)
	}
	for _, q := range []string{"limit=0", "limit=501", "limit=x", "include_deleted=maybe"} {
		if rec := do(h, http.MethodGet, "/api/v1/resources?"+q, nil, tenantHdr); rec.Code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", q, rec.Code)
		}
	}
}

func TestGetNotFound(t *testing.T) {
	h := invHandler(&fakeInventory{getErr: inventory.ErrNotFound})
	for _, p := range []string{"/api/v1/resources/x", "/api/v1/inventory/imports/x"} {
		if rec := do(h, http.MethodGet, p, nil, tenantHdr); rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", p, rec.Code)
		}
	}
}

func TestInventoryUnconfigured(t *testing.T) {
	rec := do(invHandler(nil), http.MethodGet, "/api/v1/resources", nil, tenantHdr)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
}

func TestDefaultBodyLimitStillAppliesToOtherRoutes(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", strings.NewReader(strings.Repeat("a", 2048)))
	invHandler(&fakeInventory{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d, want 413", rec.Code)
	}
}
