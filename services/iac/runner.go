package iac

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ToolRunner executes the external IaC tools.
type ToolRunner interface {
	Plan(ctx context.Context, dir string) ([]byte, error)
	Trivy(ctx context.Context, dir string) ([]byte, error)
	Checkov(ctx context.Context, dir string) ([]byte, error)
	Versions() map[string]string
}

// Images pins the tool container images.
type Images struct {
	Terraform string
	Trivy     string
	Checkov   string
}

// DefaultImages are the versions Aegis is tested with.
var DefaultImages = Images{
	Terraform: "hashicorp/terraform:1.10.5",
	Trivy:     "aquasec/trivy:0.58.1",
	Checkov:   "bridgecrew/checkov:3.2.334",
}

// DockerRunner runs every tool in a throwaway, locked-down container:
// no capabilities, no privilege escalation, pid/memory limits, and no
// network except for `terraform init` (provider download).
type DockerRunner struct {
	Docker       string // docker CLI path; default "docker"
	Images       Images
	PluginVolume string // named volume caching Terraform providers
	// MirrorVolume, if set, is a provider filesystem mirror (filled by
	// scripts/seed-terraform-mirror.sh). init then installs only from the
	// mirror and runs without network, so scans work offline.
	MirrorVolume string
	StepTimeout  time.Duration // per tool invocation
	WorkRoot     string        // parent for temporary work dirs ("" = OS temp)
}

func (d *DockerRunner) Versions() map[string]string {
	return map[string]string{"terraform": d.Images.Terraform, "trivy": d.Images.Trivy, "checkov": d.Images.Checkov}
}

// Plan copies dir to a private work directory and runs
// init (network) → validate → plan → show -json (all without network).
func (d *DockerRunner) Plan(ctx context.Context, dir string) ([]byte, error) {
	work, err := os.MkdirTemp(d.WorkRoot, "aegis-tf-")
	if err != nil {
		return nil, Retryable(fmt.Errorf("create work dir: %w", err))
	}
	defer os.RemoveAll(work)
	if err := copyTree(dir, work); err != nil {
		return nil, fmt.Errorf("copy source: %w", err)
	}

	tf := func(network bool, args ...string) ([]byte, error) {
		env := []string{"TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1", "TF_PLUGIN_CACHE_DIR=/plugin-cache",
			// Mock credentials: fixtures skip all credential checks and make no API calls.
			"AWS_ACCESS_KEY_ID=mock", "AWS_SECRET_ACCESS_KEY=mock"}
		mounts := []string{"type=bind,source=" + work + ",target=/work"}
		if d.PluginVolume != "" {
			mounts = append(mounts, "type=volume,source="+d.PluginVolume+",target=/plugin-cache")
		}
		if d.MirrorVolume != "" {
			mounts = append(mounts, "type=volume,source="+d.MirrorVolume+",target=/mirror,readonly")
			env = append(env, "TF_CLI_CONFIG_FILE=/work/.aegis-terraformrc")
		}
		return d.run(ctx, network, mounts, env, d.Images.Terraform, args...)
	}

	initNetwork := true
	if d.MirrorVolume != "" {
		// Providers come only from the read-only mirror: no registry access at all.
		rc := "provider_installation {\n  filesystem_mirror {\n    path = \"/mirror\"\n  }\n}\n"
		if err := os.WriteFile(filepath.Join(work, ".aegis-terraformrc"), []byte(rc), 0o644); err != nil {
			return nil, fmt.Errorf("write terraform config: %w", err)
		}
		initNetwork = false
	}
	if _, err := tf(initNetwork, "init", "-input=false", "-no-color"); err != nil {
		return nil, Retryable(fmt.Errorf("terraform init: %w", err)) // usually a network problem
	}
	if _, err := tf(false, "validate", "-no-color"); err != nil {
		return nil, fmt.Errorf("terraform validate: %w", err)
	}
	if _, err := tf(false, "plan", "-input=false", "-lock=false", "-refresh=false", "-no-color", "-out=tfplan"); err != nil {
		return nil, fmt.Errorf("terraform plan: %w", err)
	}
	out, err := tf(false, "show", "-json", "-no-color", "tfplan")
	if err != nil {
		return nil, fmt.Errorf("terraform show: %w", err)
	}
	return out, nil
}

func (d *DockerRunner) Trivy(ctx context.Context, dir string) ([]byte, error) {
	out, err := d.run(ctx, false, []string{"type=bind,source=" + dir + ",target=/src,readonly"}, nil, d.Images.Trivy,
		"config", "--skip-check-update", "--format", "json", "--quiet", "/src")
	if err != nil {
		return nil, fmt.Errorf("trivy: %w", err)
	}
	return out, nil
}

func (d *DockerRunner) Checkov(ctx context.Context, dir string) ([]byte, error) {
	out, err := d.run(ctx, false, []string{"type=bind,source=" + dir + ",target=/src,readonly"}, nil, d.Images.Checkov,
		"-d", "/src", "--framework", "terraform", "-o", "json", "--quiet", "--skip-download")
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 && len(bytes.TrimSpace(out)) > 0 {
		return out, nil // exit 1 means "checks failed", which is a successful scan
	}
	if err != nil {
		return nil, fmt.Errorf("checkov: %w", err)
	}
	return out, nil
}

// stepError carries a bounded excerpt of the tool's stderr.
type stepError struct {
	err    error
	stderr string
}

func (e *stepError) Error() string { return fmt.Sprintf("%v: %s", e.err, e.stderr) }
func (e *stepError) Unwrap() error { return e.err }

func (d *DockerRunner) run(ctx context.Context, network bool, mounts, env []string, image string, args ...string) ([]byte, error) {
	docker := d.Docker
	if docker == "" {
		docker = "docker"
	}
	timeout := d.StepTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	name := "aegis-tool-" + randomHex(6)
	argv := []string{"run", "--rm", "--name", name,
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--pids-limit", "512", "--memory", "2g", "--cpus", "2",
		// Read-only root filesystem; tools write only to the mounted work
		// directory, the plugin cache and a size-limited /tmp (also HOME).
		"--read-only", "--tmpfs", "/tmp:rw,exec,size=1g", "-e", "HOME=/tmp",
		"-w", "/work"}
	if !network {
		argv = append(argv, "--network", "none")
	}
	for _, m := range mounts {
		argv = append(argv, "--mount", m)
	}
	for _, e := range env {
		argv = append(argv, "-e", e)
	}
	argv = append(argv, image)
	argv = append(argv, args...)

	cmd := exec.CommandContext(ctx, docker, argv...)
	// Killing the docker CLI does not stop the container; kill it explicitly.
	// Kill the CLI first and bound the container kill: a hung daemon must not
	// keep the step (and the worker's drain) waiting forever.
	cmd.Cancel = func() error {
		err := cmd.Process.Kill()
		kctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = exec.CommandContext(kctx, docker, "kill", name).Run()
		return err
	}
	cmd.WaitDelay = 15 * time.Second
	var stdout bytes.Buffer
	stderr := &limitedBuffer{max: 8 << 10}
	cmd.Stdout = &stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, Retryable(fmt.Errorf("%s timed out or was cancelled: %w", image, ctx.Err()))
	}
	if err != nil {
		msg := stderr.String()
		if errors.Is(err, exec.ErrNotFound) || strings.Contains(msg, "Cannot connect to the Docker daemon") ||
			strings.Contains(msg, "error during connect") {
			return nil, Retryable(fmt.Errorf("docker unavailable: %w", err))
		}
		return stdout.Bytes(), &stepError{err: err, stderr: msg}
	}
	return stdout.Bytes(), nil
}

type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		if len(p) > room {
			l.buf.Write(p[:room])
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string {
	return strings.TrimSpace(strings.ToValidUTF8(l.buf.String(), ""))
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// copyTree copies regular files from src to dst, skipping Terraform working
// state. Symlinks are rejected (they could point outside the source tree).
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if e.IsDir() {
			if e.Name() == ".terraform" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if e.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symlink not allowed: %s", rel)
		}
		if strings.HasSuffix(e.Name(), ".tfstate") || strings.Contains(e.Name(), ".tfstate.") || e.Name() == "tfplan" {
			return nil
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.Create(filepath.Join(dst, rel))
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}
