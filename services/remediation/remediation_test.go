package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
)

func TestValidateOps(t *testing.T) {
	ok := [][]Op{
		{{Op: "set", Path: "configuration.public_access_block", Value: true}},
		{{Op: "set", Path: "configuration.logging.target_bucket", Value: "logs"}},
		{{Op: "remove", Path: "tags.legacy"}, {Op: "set", Path: "tags.owner", Value: "team-a"}},
	}
	for _, ops := range ok {
		if err := ValidateOps(ops); err != nil {
			t.Errorf("%v: %v", ops, err)
		}
	}
	bad := map[string][]Op{
		"empty":            nil,
		"unknown op":       {{Op: "replace", Path: "configuration.a", Value: 1}},
		"identity field":   {{Op: "set", Path: "region", Value: "us-east-1"}},
		"type field":       {{Op: "set", Path: "type", Value: "x"}},
		"relationships":    {{Op: "set", Path: "relationships.0", Value: "x"}},
		"bare prefix":      {{Op: "set", Path: "configuration", Value: map[string]any{}}},
		"nested tag":       {{Op: "set", Path: "tags.a.b", Value: "x"}},
		"too deep":         {{Op: "set", Path: "configuration.a.b.c.d.e", Value: 1}},
		"bad segment":      {{Op: "set", Path: "configuration.a b", Value: 1}},
		"secret key":       {{Op: "set", Path: "configuration.master_password", Value: "x"}},
		"null value":       {{Op: "set", Path: "configuration.a"}},
		"placeholder":      {{Op: "set", Path: "configuration.a", Value: "[REDACTED]"}},
		"non-string tag":   {{Op: "set", Path: "tags.owner", Value: 3}},
		"huge value":       {{Op: "set", Path: "configuration.a", Value: strings.Repeat("x", 17<<10)}},
		"too many":         make([]Op, maxOps+1),
		"empty path piece": {{Op: "set", Path: "configuration..a", Value: 1}},
	}
	for name, ops := range bad {
		if err := ValidateOps(ops); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func state() State {
	var cfg map[string]any
	_ = json.Unmarshal([]byte(`{"versioning":false,"nested":{"keep":1},"ingress":[{"protocol":"tcp","from_port":22,"to_port":22,"cidr_blocks":["0.0.0.0/0","10.0.0.0/8"]}]}`), &cfg)
	return State{ID: "x", Type: "storage.bucket", Region: "us-east-1", Tags: map[string]any{"owner": "a"}, Configuration: cfg}
}

func TestApplyAndMatches(t *testing.T) {
	s := state()
	ops := []Op{
		{Op: "set", Path: "configuration.versioning", Value: true},
		{Op: "set", Path: "configuration.logging.target", Value: "logs"},
		{Op: "remove", Path: "configuration.nested.keep"},
		{Op: "remove", Path: "configuration.missing.key"},
		{Op: "set", Path: "tags.cost_center", Value: "cc-1"},
	}
	out, diff, err := Apply(s, ops)
	if err != nil {
		t.Fatal(err)
	}
	if out.Configuration["versioning"] != true || out.Configuration["logging"].(map[string]any)["target"] != "logs" ||
		len(out.Configuration["nested"].(map[string]any)) != 0 || out.Tags["cost_center"] != "cc-1" {
		t.Fatalf("applied: %+v", out)
	}
	if len(diff) != 4 { // the no-op remove is not a change
		t.Errorf("diff: %+v", diff)
	}
	if s.Configuration["versioning"] != false || s.Tags["cost_center"] != nil {
		t.Error("Apply modified its input")
	}
	if ok, mm := Matches(out, ops); !ok {
		t.Errorf("patched state should match: %v", mm)
	}
	if ok, mm := Matches(s, ops); ok || len(mm) != 4 {
		t.Errorf("original state should not match: %v", mm)
	}
	if _, _, err := Apply(s, []Op{{Op: "set", Path: "configuration.versioning.x", Value: 1}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("writing through a scalar: %v", err)
	}
	// Numbers compare by value after a JSON round trip (imported state has float64).
	if ok, _ := Matches(State{Configuration: map[string]any{"n": 3.0}}, []Op{{Op: "set", Path: "configuration.n", Value: 3}}); !ok {
		t.Error("3 and 3.0 must match")
	}
}

func TestNetworkTemplate(t *testing.T) {
	var cfg map[string]any
	_ = json.Unmarshal([]byte(`{"ingress":[
		{"protocol":"tcp","from_port":22,"to_port":22,"cidr_blocks":["0.0.0.0/0"]},
		{"protocol":"tcp","from_port":3389,"to_port":3389,"cidr_blocks":["0.0.0.0/0","10.0.0.0/8"],"ipv6_cidr_blocks":["::/0"]},
		{"protocol":"tcp","from_port":443,"to_port":443,"cidr_blocks":["0.0.0.0/0"]}]}`), &cfg)
	s := State{Type: "network.security_group", Configuration: cfg}
	_, ops, err := FromTemplate("AEGIS-NET-001", s)
	if err != nil {
		t.Fatal(err)
	}
	ingress := ops[0].Value.([]any)
	got, _ := json.Marshal(ingress)
	want := `[{"cidr_blocks":["10.0.0.0/8"],"from_port":3389,"ipv6_cidr_blocks":["::/0"],"protocol":"tcp","to_port":3389},{"cidr_blocks":["0.0.0.0/0"],"from_port":443,"protocol":"tcp","to_port":443}]`
	if string(got) != want {
		t.Errorf("ingress after NET-001 fix:\n got %s\nwant %s", got, want)
	}
	if cfg["ingress"].([]any)[0].(map[string]any)["cidr_blocks"].([]any)[0] != "0.0.0.0/0" {
		t.Error("template modified the input state")
	}
	if _, _, err := FromTemplate("AEGIS-NET-001", State{Configuration: map[string]any{"ingress": []any{}}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("no ingress: %v", err)
	}
	if _, _, err := FromTemplate("AEGIS-IAM-001", s); !errors.Is(err, ErrNoTemplate) {
		t.Errorf("IAM has no template: %v", err)
	}
	if n := len(Templates()); n != 8 || Templates()[0].RuleID != "AEGIS-DB-001" || !Templates()[0].Disruptive {
		t.Errorf("templates: %d %+v", n, Templates()[0])
	}
}

// fakePolicy fails versioning-disabled buckets (S3-002) and buckets whose
// public_access_block is not true (S3-001).
type fakePolicy struct{}

func (fakePolicy) Bundle(context.Context) (opa.Bundle, error) { return opa.Bundle{SHA256: "b"}, nil }
func (fakePolicy) Query(_ context.Context, _ string, input any, out any) error {
	st := input.(map[string]any)["resources"].([]State)[0]
	var deny []map[string]string
	if st.Configuration["public_access_block"] != true {
		deny = append(deny, map[string]string{"rule_id": "AEGIS-S3-001"})
	}
	if st.Configuration["versioning"] != true {
		deny = append(deny, map[string]string{"rule_id": "AEGIS-S3-002"})
	}
	raw, _ := json.Marshal(map[string]any{"deny": deny})
	return json.Unmarshal(raw, out)
}

func TestSimulateGate(t *testing.T) {
	s := &Service{OPA: fakePolicy{}}
	r := resource{state: State{Configuration: map[string]any{"public_access_block": true, "versioning": false}}}
	for _, tc := range []struct {
		name    string
		ops     []Op
		target  string
		passed  bool
		reasons string
	}{
		{"fixes target", []Op{{Op: "set", Path: "configuration.versioning", Value: true}}, "AEGIS-S3-002", true, ""},
		{"breaks another rule", []Op{{Op: "set", Path: "configuration.versioning", Value: true}, {Op: "set", Path: "configuration.public_access_block", Value: false}}, "AEGIS-S3-002", false, "introduces failing rules: AEGIS-S3-001"},
		{"does not fix target", []Op{{Op: "set", Path: "tags.owner", Value: "x"}}, "AEGIS-S3-002", false, "AEGIS-S3-002 still fails"},
		{"no change", []Op{{Op: "set", Path: "configuration.public_access_block", Value: true}}, "", false, "do not change"},
		{"manual, harmless", []Op{{Op: "set", Path: "tags.owner", Value: "x"}}, "", true, ""},
	} {
		sim, err := s.simulate(context.Background(), r, tc.ops, tc.target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if sim.Passed != tc.passed || (tc.reasons != "" && !strings.Contains(strings.Join(sim.BlockedReasons, "; "), tc.reasons)) {
			t.Errorf("%s: passed=%v reasons=%v", tc.name, sim.Passed, sim.BlockedReasons)
		}
	}
}
