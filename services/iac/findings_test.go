package iac

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func open(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestParseTrivyGolden(t *testing.T) {
	fs, err := ParseTrivy(open(t, "insecure-storage.trivy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 23 { // MisconfSummary.Failures in the recorded output
		t.Fatalf("got %d trivy findings, want 23", len(fs))
	}
	var sawPublicBucket bool
	for _, f := range fs {
		if f.Source != SourceTrivy || f.ResourceAddress == "" || f.StartLine == 0 || f.RuleID == "" {
			t.Errorf("incomplete finding: %+v", f)
		}
		if f.ResourceAddress == "aws_s3_bucket_public_access_block.public_assets" {
			sawPublicBucket = true
		}
		if strings.Contains(f.Title, "\x1b[") {
			t.Error("ANSI escape codes leaked into title")
		}
	}
	if !sawPublicBucket {
		t.Error("trivy did not flag the permissive public access block")
	}
}

func TestParseCheckovGolden(t *testing.T) {
	fs, err := ParseCheckov(open(t, "insecure-storage.checkov.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 28 { // summary.failed in the recorded output
		t.Fatalf("got %d checkov findings, want 28", len(fs))
	}
	for _, f := range fs {
		if f.Severity != "unknown" {
			t.Errorf("OSS checkov has no severity; got %q", f.Severity)
		}
		if strings.HasPrefix(f.FilePath, "/") || f.StartLine == 0 {
			t.Errorf("bad location: %+v", f)
		}
	}
}

func TestParseCheckovArrayForm(t *testing.T) {
	arr := `[{"results":{"failed_checks":[{"check_id":"CKV_A","resource":"r.a","file_path":"/a.tf","file_line_range":[1,2]}]}},
	        {"results":{"failed_checks":[{"check_id":"CKV_B","resource":"r.b","file_path":"/b.tf","file_line_range":[3,4]}]}}]`
	fs, err := ParseCheckov(strings.NewReader(arr))
	if err != nil || len(fs) != 2 {
		t.Fatalf("array form: %v %+v", err, fs)
	}
	if _, err := ParseCheckov(strings.NewReader("  ")); err == nil {
		t.Error("empty output must be an error")
	}
}

func TestMergeDedupesAndSorts(t *testing.T) {
	a := Finding{Source: SourceTrivy, RuleID: "X", Severity: "low", ResourceAddress: "b"}
	b := Finding{Source: SourcePolicy, RuleID: "Y", Severity: "critical", ResourceAddress: "a"}
	out := Merge([]Finding{a, a}, []Finding{b})
	if len(out) != 2 || out[0].RuleID != "Y" || out[0].Fingerprint == "" {
		t.Fatalf("merge: %+v", out)
	}
}

func TestNormSeverity(t *testing.T) {
	for in, want := range map[string]string{"HIGH": "high", " Critical ": "critical", "": "unknown", "weird": "unknown"} {
		if got := normSeverity(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestOPAClient(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/data/aegis/terraform" {
			http.NotFound(w, r)
			return
		}
		b := make([]byte, r.ContentLength)
		r.Body.Read(b)
		gotBody = string(b)
		fmt.Fprint(w, `{"result":{"deny":[{"rule_id":"AEGIS-S3-001","severity":"high","address":"aws_s3_bucket.a"}],"warn":[]}}`)
	}))
	defer srv.Close()
	res, err := (&OPAClient{BaseURL: srv.URL}).Evaluate(context.Background(), Analysis{Resources: []PlannedResource{{Address: "aws_s3_bucket.a"}}})
	if err != nil || len(res.Deny) != 1 || res.Findings()[0].Decision != "deny" {
		t.Fatalf("evaluate: %v %+v", err, res)
	}
	if !strings.Contains(gotBody, `"input":{"resources":[`) {
		t.Errorf("unexpected request body: %s", gotBody)
	}
}

func TestOPAClientFailsClosed(t *testing.T) {
	undefined := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{}`) }))
	defer undefined.Close()
	if _, err := (&OPAClient{BaseURL: undefined.URL}).Evaluate(context.Background(), Analysis{}); err == nil || IsRetryable(err) {
		t.Errorf("undefined policy must be a permanent error, got %v", err)
	}

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer broken.Close()
	if _, err := (&OPAClient{BaseURL: broken.URL}).Evaluate(context.Background(), Analysis{}); !IsRetryable(err) {
		t.Errorf("5xx must be retryable, got %v", err)
	}

	if _, err := (&OPAClient{BaseURL: "http://127.0.0.1:1"}).Evaluate(context.Background(), Analysis{}); !IsRetryable(err) {
		t.Errorf("connection refused must be retryable, got %v", err)
	}
}

func TestIsRetryable(t *testing.T) {
	if !IsRetryable(fmt.Errorf("wrap: %w", Retryable(errors.New("x")))) || !IsRetryable(context.DeadlineExceeded) {
		t.Error("expected retryable")
	}
	if IsRetryable(errors.New("plain")) || Retryable(nil) != nil {
		t.Error("unexpected retryable")
	}
}
