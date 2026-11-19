package iac

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The test binary doubles as a fake docker CLI: when AEGIS_FAKE_DOCKER_LOG is
// set it records its arguments (one invocation per line) and behaves as the
// variables below say, instead of running the tests.
func TestMain(m *testing.M) {
	if log := os.Getenv("AEGIS_FAKE_DOCKER_LOG"); log != "" {
		fakeDocker(log)
		return
	}
	os.Exit(m.Run())
}

func fakeDocker(log string) {
	args := os.Args[1:]
	f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		fmt.Fprintln(f, strings.Join(args, "\x1f"))
		f.Close()
	}
	if msg := os.Getenv("AEGIS_FAKE_DOCKER_FAIL"); msg != "" && len(args) > 0 && args[0] == "run" {
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(1)
	}
	if len(args) > 0 && args[len(args)-1] == "tfplan" { // terraform show -json tfplan
		fmt.Print(`{"format_version":"1.2"}`)
	}
	os.Exit(0)
}

func fakeRunner(t *testing.T, mirror string) (*DockerRunner, func() [][]string) {
	t.Helper()
	log := filepath.Join(t.TempDir(), "docker.log")
	t.Setenv("AEGIS_FAKE_DOCKER_LOG", log)
	d := &DockerRunner{Docker: os.Args[0], Images: DefaultImages, MirrorVolume: mirror, WorkRoot: t.TempDir()}
	calls := func() [][]string {
		raw, err := os.ReadFile(log)
		if err != nil {
			t.Fatal(err)
		}
		var out [][]string
		for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			out = append(out, strings.Split(l, "\x1f"))
		}
		return out
	}
	return d, calls
}

func has(argv []string, seq ...string) bool {
	for i := 0; i+len(seq) <= len(argv); i++ {
		if strings.Join(argv[i:i+len(seq)], "\x00") == strings.Join(seq, "\x00") {
			return true
		}
	}
	return false
}

func step(argv []string) string {
	for _, img := range []string{DefaultImages.Terraform, DefaultImages.Trivy, DefaultImages.Checkov} {
		for i, a := range argv {
			if a == img && i+1 < len(argv) {
				return img + " " + argv[i+1]
			}
		}
	}
	return strings.Join(argv, " ")
}

// The container is the primary sandbox for untrusted Terraform: every tool
// step must run locked down, and only a non-mirror `terraform init` may use
// the network.
func TestDockerRunnerSandboxFlags(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.tf"), []byte("# empty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mirror := range []string{"", "aegis-tf-mirror"} {
		d, calls := fakeRunner(t, mirror)
		ctx := context.Background()
		if _, err := d.Plan(ctx, src); err != nil {
			t.Fatalf("mirror=%q plan: %v", mirror, err)
		}
		if _, err := d.Trivy(ctx, src); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Checkov(ctx, src); err != nil {
			t.Fatal(err)
		}
		runs := calls()
		if len(runs) != 6 { // init, validate, plan, show, trivy, checkov
			t.Fatalf("mirror=%q: %d docker runs, want 6", mirror, len(runs))
		}
		for _, argv := range runs {
			name := step(argv)
			for _, flag := range [][]string{{"--cap-drop", "ALL"}, {"--security-opt", "no-new-privileges"}, {"--read-only"}, {"--pids-limit", "512"}} {
				if !has(argv, flag...) {
					t.Errorf("mirror=%q %s: missing %v", mirror, name, flag)
				}
			}
			networked := name == DefaultImages.Terraform+" init" && mirror == ""
			if got := has(argv, "--network", "none"); got == networked {
				t.Errorf("mirror=%q %s: --network none = %v, want %v", mirror, name, got, !networked)
			}
		}
	}
}

func TestDockerUnavailableIsRetryable(t *testing.T) {
	d, _ := fakeRunner(t, "")
	t.Setenv("AEGIS_FAKE_DOCKER_FAIL", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
	_, err := d.Trivy(context.Background(), t.TempDir())
	if err == nil || !IsRetryable(err) {
		t.Fatalf("err = %v, want a retryable error", err)
	}
	t.Setenv("AEGIS_FAKE_DOCKER_FAIL", "Error: invalid configuration")
	if _, err := d.Trivy(context.Background(), t.TempDir()); err == nil || IsRetryable(err) {
		t.Fatalf("err = %v, want a permanent error", err)
	}
}
