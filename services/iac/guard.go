package iac

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Pre-flight limits for a Terraform source tree.
const (
	maxSourceFiles = 200
	maxSourceBytes = 5 << 20
)

var (
	fixtureName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

	// `terraform plan` executes the program of an "external" data source and
	// provider plugins; these patterns block the known code-execution paths.
	externalData   = regexp.MustCompile(`data\s+"external"`)
	provisioner    = regexp.MustCompile(`provisioner\s+"`)
	moduleSource   = regexp.MustCompile(`(?s)module\s+"[^"]+"\s*\{[^}]*?source\s*=\s*"([^"]+)"`)
	providerSource = regexp.MustCompile(`(?m)^\s*source\s*=\s*"([a-z0-9-]+/[a-z0-9-]+)"`)
)

// AllowedProviders may be downloaded and executed during planning.
var AllowedProviders = map[string]bool{"hashicorp/aws": true, "hashicorp/random": true}

// ErrRejected is returned for sources that fail pre-flight checks.
var ErrRejected = errors.New("terraform source rejected")

// ResolveFixture maps a fixture name to a directory strictly inside root.
func ResolveFixture(root, name string) (string, error) {
	if !fixtureName.MatchString(name) {
		return "", fmt.Errorf("%w: invalid fixture name %q", ErrRejected, name)
	}
	absRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("fixtures directory: %w", err)
	}
	absRoot, _ = filepath.Abs(absRoot)
	dir, err := filepath.EvalSymlinks(filepath.Join(absRoot, name))
	if err != nil {
		return "", fmt.Errorf("%w: unknown fixture %q", ErrRejected, name)
	}
	rel, err := filepath.Rel(absRoot, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || strings.ContainsRune(rel, filepath.Separator) {
		return "", fmt.Errorf("%w: fixture %q escapes the fixtures directory", ErrRejected, name)
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return "", fmt.Errorf("%w: unknown fixture %q", ErrRejected, name)
	}
	return dir, nil
}

// Preflight statically rejects Terraform sources that could execute code or
// exhaust resources during planning. It is defence in depth: the sandboxed
// container is the primary control.
func Preflight(dir string) error {
	var files, total int
	var problems []string
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			if e.Name() == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		if e.Type()&fs.ModeSymlink != 0 {
			problems = append(problems, rel+": symlinks are not allowed")
			return nil
		}
		files++
		info, err := e.Info()
		if err != nil {
			return err
		}
		total += int(info.Size())
		if !strings.HasSuffix(p, ".tf") {
			if strings.HasSuffix(p, ".tf.json") {
				problems = append(problems, rel+": JSON-syntax Terraform is not supported")
			}
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		src := string(b)
		if externalData.MatchString(src) {
			problems = append(problems, rel+`: data "external" executes arbitrary programs`)
		}
		if provisioner.MatchString(src) {
			problems = append(problems, rel+": provisioners are not allowed")
		}
		for _, m := range moduleSource.FindAllStringSubmatch(src, -1) {
			if !strings.HasPrefix(m[1], "./") && !strings.HasPrefix(m[1], "../") {
				problems = append(problems, fmt.Sprintf("%s: remote module source %q is not allowed", rel, m[1]))
			}
		}
		for _, m := range providerSource.FindAllStringSubmatch(src, -1) {
			if !AllowedProviders[m[1]] {
				problems = append(problems, fmt.Sprintf("%s: provider %q is not on the allow-list", rel, m[1]))
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("inspect source: %w", err)
	}
	if files > maxSourceFiles {
		problems = append(problems, fmt.Sprintf("too many files (%d > %d)", files, maxSourceFiles))
	}
	if total > maxSourceBytes {
		problems = append(problems, fmt.Sprintf("source too large (%d > %d bytes)", total, maxSourceBytes))
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%w: %s", ErrRejected, strings.Join(problems, "; "))
	}
	return nil
}
