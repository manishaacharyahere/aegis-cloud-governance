package iac

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
)

// Finding sources.
const (
	SourcePolicy  = "aegis-policy"
	SourceTrivy   = "trivy"
	SourceCheckov = "checkov"
)

// Finding is one result from any analyser, in a single normalised shape.
type Finding struct {
	Source          string `json:"source"`
	RuleID          string `json:"rule_id"`
	Severity        string `json:"severity"` // critical, high, medium, low, info, unknown
	Decision        string `json:"decision"` // deny or warn (policy); fail (scanners)
	ResourceAddress string `json:"resource_address"`
	FilePath        string `json:"file_path,omitempty"`
	StartLine       int    `json:"start_line,omitempty"`
	EndLine         int    `json:"end_line,omitempty"`
	Title           string `json:"title"`
	Fingerprint     string `json:"fingerprint"`
}

func (f *Finding) fingerprint() {
	h := sha256.Sum256([]byte(strings.Join([]string{f.Source, f.RuleID, f.ResourceAddress, f.FilePath,
		fmt.Sprint(f.StartLine)}, "\x00")))
	f.Fingerprint = hex.EncodeToString(h[:16])
}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

func normSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, ok := severityRank[s]; ok {
		return s
	}
	return "unknown"
}

// ParseTrivy extracts failed misconfigurations from `trivy config --format json`.
func ParseTrivy(r io.Reader) ([]Finding, error) {
	var doc struct {
		Results []struct {
			Target            string `json:"Target"`
			Misconfigurations []struct {
				ID            string `json:"ID"`
				Title         string `json:"Title"`
				Severity      string `json:"Severity"`
				Status        string `json:"Status"`
				CauseMetadata struct {
					Resource  string `json:"Resource"`
					StartLine int    `json:"StartLine"`
					EndLine   int    `json:"EndLine"`
				} `json:"CauseMetadata"`
			} `json:"Misconfigurations"`
		} `json:"Results"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode trivy output: %w", err)
	}
	var out []Finding
	for _, res := range doc.Results {
		for _, m := range res.Misconfigurations {
			if m.Status != "FAIL" {
				continue
			}
			out = append(out, Finding{
				Source: SourceTrivy, RuleID: m.ID, Severity: normSeverity(m.Severity), Decision: "fail",
				ResourceAddress: m.CauseMetadata.Resource, FilePath: res.Target,
				StartLine: m.CauseMetadata.StartLine, EndLine: m.CauseMetadata.EndLine, Title: m.Title,
			})
		}
	}
	return out, nil
}

// ParseCheckov extracts failed checks from `checkov -o json`. Checkov emits
// an object for one framework and an array for several; both are handled.
// Open-source Checkov reports no severities, so they are recorded as unknown.
func ParseCheckov(r io.Reader) ([]Finding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	type report struct {
		Results struct {
			FailedChecks []struct {
				CheckID       string `json:"check_id"`
				CheckName     string `json:"check_name"`
				Resource      string `json:"resource"`
				FilePath      string `json:"file_path"`
				FileLineRange []int  `json:"file_line_range"`
				Severity      string `json:"severity"`
			} `json:"failed_checks"`
		} `json:"results"`
	}
	var reports []report
	trimmed := bytes.TrimSpace(raw)
	switch {
	case len(trimmed) == 0:
		return nil, errors.New("empty checkov output")
	case trimmed[0] == '[':
		err = json.Unmarshal(trimmed, &reports)
	default:
		var one report
		err = json.Unmarshal(trimmed, &one)
		reports = []report{one}
	}
	if err != nil {
		return nil, fmt.Errorf("decode checkov output: %w", err)
	}
	var out []Finding
	for _, rep := range reports {
		for _, c := range rep.Results.FailedChecks {
			f := Finding{
				Source: SourceCheckov, RuleID: c.CheckID, Severity: normSeverity(c.Severity), Decision: "fail",
				ResourceAddress: c.Resource, FilePath: strings.TrimPrefix(c.FilePath, "/"), Title: c.CheckName,
			}
			if len(c.FileLineRange) == 2 {
				f.StartLine, f.EndLine = c.FileLineRange[0], c.FileLineRange[1]
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// PolicyResult is the OPA decision for a plan.
type PolicyResult struct {
	Deny []PolicyFinding `json:"deny"`
	Warn []PolicyFinding `json:"warn"`
}

// PolicyFinding is one finding produced by the Rego policies.
type PolicyFinding struct {
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	Address      string `json:"address"`
	ResourceType string `json:"resource_type"`
	Message      string `json:"message"`
}

// Findings converts policy output to normalised findings.
func (p PolicyResult) Findings() []Finding {
	var out []Finding
	add := func(list []PolicyFinding, decision string) {
		for _, f := range list {
			out = append(out, Finding{Source: SourcePolicy, RuleID: f.RuleID, Severity: normSeverity(f.Severity),
				Decision: decision, ResourceAddress: f.Address, Title: f.Message})
		}
	}
	add(p.Deny, "deny")
	add(p.Warn, "warn")
	return out
}

// Merge fingerprints, de-duplicates and sorts findings (severity, address, source, rule).
func Merge(groups ...[]Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, g := range groups {
		for _, f := range g {
			f.fingerprint()
			if seen[f.Fingerprint] {
				continue
			}
			seen[f.Fingerprint] = true
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if a.ResourceAddress != b.ResourceAddress {
			return a.ResourceAddress < b.ResourceAddress
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		return a.RuleID < b.RuleID
	})
	return out
}

// PolicyEvaluator evaluates plan analyses against the policy set.
type PolicyEvaluator interface {
	Evaluate(ctx context.Context, a Analysis) (PolicyResult, error)
	Bundle(ctx context.Context) (opa.Bundle, error)
}

// OPAClient evaluates the aegis.terraform policies on an OPA server.
type OPAClient struct {
	BaseURL string // e.g. http://127.0.0.1:8181
	HTTP    *http.Client
}

func (c *OPAClient) client() *opa.Client { return &opa.Client{BaseURL: c.BaseURL, HTTP: c.HTTP} }

// Evaluate queries data.aegis.terraform. It fails closed: an undefined
// document (policy not loaded) is an error, never "no findings".
func (c *OPAClient) Evaluate(ctx context.Context, a Analysis) (PolicyResult, error) {
	var out PolicyResult
	err := c.client().Query(ctx, "aegis.terraform", map[string]any{"resources": a.Resources}, &out)
	return out, classifyOPA(err)
}

// Bundle returns the exact policy text OPA is serving.
func (c *OPAClient) Bundle(ctx context.Context) (opa.Bundle, error) {
	b, err := c.client().Bundle(ctx)
	return b, classifyOPA(err)
}

func classifyOPA(err error) error {
	var u *opa.UnavailableError
	if errors.As(err, &u) {
		return Retryable(err)
	}
	return err
}

// RetryableError marks failures worth retrying (network, timeouts, tooling
// availability). Everything else is permanent.
type RetryableError struct{ Err error }

func (e *RetryableError) Error() string { return e.Err.Error() }
func (e *RetryableError) Unwrap() error { return e.Err }

// Retryable wraps err as retryable.
func Retryable(err error) error {
	if err == nil {
		return nil
	}
	return &RetryableError{Err: err}
}

// IsRetryable reports whether err (or a wrapped error) is retryable.
func IsRetryable(err error) bool {
	var r *RetryableError
	return errors.As(err, &r) || errors.Is(err, context.DeadlineExceeded)
}
