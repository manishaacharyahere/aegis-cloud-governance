package iac

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
)

// Result is the complete, redacted output of one scan.
type Result struct {
	Analysis           Analysis          `json:"analysis"`
	Findings           []Finding         `json:"findings"`
	ToolVersions       map[string]string `json:"tool_versions"`
	PolicyBundleSHA256 string            `json:"policy_bundle_sha256"`
	PolicyBundle       opa.Bundle        `json:"-"`
}

// Pipeline wires the tools and policy engine into one scan.
type Pipeline struct {
	Tools       ToolRunner
	Policy      PolicyEvaluator
	FixturesDir string
}

// Run scans the named fixture. Terraform planning and both scanners run
// concurrently; OPA evaluates the plan once it exists. Any failure fails the
// scan, because a partial report would understate risk.
func (p *Pipeline) Run(ctx context.Context, fixture string) (Result, error) {
	dir, err := ResolveFixture(p.FixturesDir, fixture)
	if err != nil {
		return Result{}, err
	}
	if err := Preflight(dir); err != nil {
		return Result{}, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg                            sync.WaitGroup
		once                          sync.Once
		firstErr                      error
		planOut, trivyOut, checkovOut []byte
	)
	// The first failure is the root cause; it cancels the sibling steps.
	fail := func(err error) {
		if err != nil {
			once.Do(func() { firstErr = err; cancel() })
		}
	}
	wg.Add(3)
	go func() { defer wg.Done(); var err error; planOut, err = p.Tools.Plan(ctx, dir); fail(err) }()
	go func() { defer wg.Done(); var err error; trivyOut, err = p.Tools.Trivy(ctx, dir); fail(err) }()
	go func() { defer wg.Done(); var err error; checkovOut, err = p.Tools.Checkov(ctx, dir); fail(err) }()
	wg.Wait()
	if firstErr != nil {
		return Result{}, firstErr
	}

	plan, err := ParsePlan(bytes.NewReader(planOut))
	if err != nil {
		return Result{}, fmt.Errorf("parse plan: %w", err)
	}
	analysis := Analyze(plan)

	// Record the policy version actually served for this evaluation.
	bundle, err := p.Policy.Bundle(ctx)
	if err != nil {
		return Result{}, err
	}
	policy, err := p.Policy.Evaluate(ctx, analysis)
	if err != nil {
		return Result{}, err
	}
	trivy, err := ParseTrivy(bytes.NewReader(trivyOut))
	if err != nil {
		return Result{}, err
	}
	checkov, err := ParseCheckov(bytes.NewReader(checkovOut))
	if err != nil {
		return Result{}, err
	}

	return Result{
		Analysis:           analysis,
		Findings:           Merge(policy.Findings(), trivy, checkov),
		ToolVersions:       p.Tools.Versions(),
		PolicyBundleSHA256: bundle.SHA256,
		PolicyBundle:       bundle,
	}, nil
}
