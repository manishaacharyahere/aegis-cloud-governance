package iac

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixturesDir = "../../datasets/terraform-fixtures"

// goldenTools replays the recorded tool outputs from testdata.
type goldenTools struct {
	fixture  string
	trivyErr error
	planErr  error
}

func (g goldenTools) read(kind string) ([]byte, error) {
	return os.ReadFile(filepath.Join("testdata", g.fixture+"."+kind+".json"))
}
func (g goldenTools) Plan(ctx context.Context, _ string) ([]byte, error) {
	if g.planErr != nil {
		return nil, g.planErr
	}
	return g.read("plan")
}
func (g goldenTools) Trivy(ctx context.Context, _ string) ([]byte, error) {
	if g.trivyErr != nil {
		return nil, g.trivyErr
	}
	return g.read("trivy")
}
func (g goldenTools) Checkov(ctx context.Context, _ string) ([]byte, error) { return g.read("checkov") }
func (g goldenTools) Versions() map[string]string                           { return map[string]string{"terraform": "test"} }

type fakePolicy struct {
	res PolicyResult
	err error
	got Analysis
}

func (f *fakePolicy) Evaluate(_ context.Context, a Analysis) (PolicyResult, error) {
	f.got = a
	return f.res, f.err
}

func TestPipelineMergesAllSources(t *testing.T) {
	pol := &fakePolicy{res: PolicyResult{Deny: []PolicyFinding{{RuleID: "AEGIS-DB-002", Severity: "critical", Address: "aws_db_instance.legacy"}}}}
	p := &Pipeline{Tools: goldenTools{fixture: "insecure-storage"}, Policy: pol, FixturesDir: fixturesDir, PolicyBundleSHA: "abc"}
	res, err := p.Run(context.Background(), "insecure-storage")
	if err != nil {
		t.Fatal(err)
	}
	if len(pol.got.Resources) != 4 {
		t.Errorf("policy saw %d resources", len(pol.got.Resources))
	}
	counts := map[string]int{}
	for _, f := range res.Findings {
		counts[f.Source]++
	}
	if counts[SourcePolicy] != 1 || counts[SourceTrivy] != 23 || counts[SourceCheckov] != 28 {
		t.Errorf("source counts %v", counts)
	}
	if res.Findings[0].Severity != "critical" {
		t.Errorf("findings not sorted by severity: first=%+v", res.Findings[0])
	}
	if res.PolicyBundleSHA256 != "abc" || res.ToolVersions["terraform"] != "test" {
		t.Errorf("provenance missing: %+v", res)
	}
}

func TestPipelineFailures(t *testing.T) {
	boom := errors.New("trivy crashed")
	cases := map[string]struct {
		p       *Pipeline
		fixture string
		want    error
	}{
		"traversal":   {&Pipeline{Tools: goldenTools{}, Policy: &fakePolicy{}, FixturesDir: fixturesDir}, "../secrets", ErrRejected},
		"unknown":     {&Pipeline{Tools: goldenTools{}, Policy: &fakePolicy{}, FixturesDir: fixturesDir}, "does-not-exist", ErrRejected},
		"scanner":     {&Pipeline{Tools: goldenTools{fixture: "iam-wildcard", trivyErr: boom}, Policy: &fakePolicy{}, FixturesDir: fixturesDir}, "iam-wildcard", boom},
		"policy down": {&Pipeline{Tools: goldenTools{fixture: "iam-wildcard"}, Policy: &fakePolicy{err: Retryable(errors.New("opa down"))}, FixturesDir: fixturesDir}, "iam-wildcard", nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := c.p.Run(context.Background(), c.fixture)
			if err == nil {
				t.Fatal("expected error")
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if name == "policy down" && !IsRetryable(err) {
				t.Fatalf("OPA outage must be retryable: %v", err)
			}
		})
	}
}

func writeTF(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestPreflight(t *testing.T) {
	ok := writeTF(t, map[string]string{"main.tf": `
terraform { required_providers { aws = { source = "hashicorp/aws" } } }
module "net" { source = "./modules/net" }`})
	if err := Preflight(ok); err != nil {
		t.Fatalf("clean source rejected: %v", err)
	}

	bad := map[string]string{
		"external data": `data "external" "x" { program = ["sh", "-c", "curl evil"] }`,
		"provisioner":   `resource "null_resource" "x" { provisioner "local-exec" { command = "id" } }`,
		"remote module": `module "m" { source = "git::https://example.com/m.git" }`,
		"registry mod":  `module "m" { source = "terraform-aws-modules/vpc/aws" }`,
		"provider":      "terraform {\n required_providers {\n x = {\n source = \"evil/backdoor\"\n }\n }\n}",
	}
	for name, src := range bad {
		t.Run(name, func(t *testing.T) {
			err := Preflight(writeTF(t, map[string]string{"main.tf": src}))
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("want ErrRejected, got %v", err)
			}
		})
	}
	if err := Preflight(writeTF(t, map[string]string{"main.tf.json": "{}"})); !errors.Is(err, ErrRejected) {
		t.Errorf("tf.json should be rejected: %v", err)
	}
}

func TestAllFixturesPassPreflight(t *testing.T) {
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir, err := ResolveFixture(fixturesDir, e.Name())
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if err := Preflight(dir); err != nil {
			t.Errorf("%s: %v", e.Name(), err)
		}
	}
}

func TestResolveFixtureRejectsBadNames(t *testing.T) {
	for _, name := range []string{"", "..", "../x", "a/b", `a\b`, "UPPER", "-lead", strings.Repeat("a", 70)} {
		if _, err := ResolveFixture(fixturesDir, name); !errors.Is(err, ErrRejected) {
			t.Errorf("%q accepted: %v", name, err)
		}
	}
}

func TestHashPoliciesIgnoresTestsAndIsStable(t *testing.T) {
	dir := writeTF(t, map[string]string{"a.rego": "package a", "a_test.rego": "package a_test"})
	h1, err := HashPolicies(dir)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a_test.rego"), []byte("changed"), 0o644)
	h2, _ := HashPolicies(dir)
	os.WriteFile(filepath.Join(dir, "a.rego"), []byte("package a\n"), 0o644)
	h3, _ := HashPolicies(dir)
	if h1 != h2 || h1 == h3 {
		t.Errorf("hash stability: %s %s %s", h1, h2, h3)
	}
}

func TestCopyTreeSkipsStateAndTerraformDir(t *testing.T) {
	src := writeTF(t, map[string]string{"main.tf": "x", "terraform.tfstate": "secret", "tfplan": "bin"})
	os.MkdirAll(filepath.Join(src, ".terraform", "providers"), 0o755)
	os.WriteFile(filepath.Join(src, ".terraform", "providers", "p"), []byte("big"), 0o644)
	dst := t.TempDir()
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"terraform.tfstate", "tfplan", ".terraform"} {
		if _, err := os.Stat(filepath.Join(dst, p)); err == nil {
			t.Errorf("%s should not be copied", p)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "main.tf")); err != nil {
		t.Error("main.tf not copied")
	}
}
