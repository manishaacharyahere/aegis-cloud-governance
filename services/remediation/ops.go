// Package remediation is Module H: controlled, approval-gated remediation.
//
// A remediation is a small patch to one resource's configuration or tags.
// Aegis simulates it by re-running the same OPA policies on a patched copy,
// pins the result to the resource version it was simulated against, requires
// approval by people other than the requester, and then releases a change set
// to be applied through the normal change pipeline. Aegis never calls a cloud
// API and never runs Terraform apply. Verification compares the next imported
// inventory with what was approved.
package remediation

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/redact"
)

// Op is one change. Path is "configuration.<key>[.<key>...]" or "tags.<key>".
type Op struct {
	Op    string `json:"op"` // set | remove
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// State is the policy-relevant view of a resource (the OPA input document).
type State = opa.Resource

// Change is one field difference produced by applying ops.
type Change struct {
	Path   string `json:"path"`
	Before any    `json:"before"`
	After  any    `json:"after"`
}

// ErrInvalid is returned for malformed requests.
var ErrInvalid = errors.New("invalid request")

const (
	maxOps        = 20
	maxValueBytes = 16 << 10
	maxDepth      = 4
)

var segmentRe = regexp.MustCompile(`^[A-Za-z0-9_:-]{1,128}$`)

// ValidateOps checks every op before anything is simulated. Only
// configuration and tags can change: never identity, type, region or
// relationships, and never a key that looks like a secret.
func ValidateOps(ops []Op) error {
	if len(ops) == 0 || len(ops) > maxOps {
		return fmt.Errorf("%w: between 1 and %d operations are required", ErrInvalid, maxOps)
	}
	var problems []string
	for i, o := range ops {
		segs := strings.Split(o.Path, ".")
		switch {
		case o.Op != "set" && o.Op != "remove":
			problems = append(problems, fmt.Sprintf("operations[%d].op must be set or remove", i))
		case len(segs) < 2 || (segs[0] != "configuration" && segs[0] != "tags"):
			problems = append(problems, fmt.Sprintf("operations[%d].path must start with configuration. or tags.", i))
		case segs[0] == "tags" && len(segs) != 2, len(segs) > maxDepth+1:
			problems = append(problems, fmt.Sprintf("operations[%d].path is too deep", i))
		default:
			for _, s := range segs[1:] {
				if !segmentRe.MatchString(s) {
					problems = append(problems, fmt.Sprintf("operations[%d].path has an invalid segment %q", i, s))
				} else if redact.IsSensitiveKey(s) {
					problems = append(problems, fmt.Sprintf("operations[%d].path targets a secret-like key; secrets are not managed by remediation", i))
				}
			}
		}
		if o.Op == "set" {
			raw, err := json.Marshal(o.Value)
			if err != nil || len(raw) > maxValueBytes || o.Value == nil {
				problems = append(problems, fmt.Sprintf("operations[%d].value must be non-null JSON of at most 16 KiB", i))
			}
			if s, ok := o.Value.(string); ok && s == redact.Placeholder {
				problems = append(problems, fmt.Sprintf("operations[%d].value cannot be the redaction placeholder", i))
			}
		}
		if segs[0] == "tags" && o.Op == "set" {
			if _, ok := o.Value.(string); !ok {
				problems = append(problems, fmt.Sprintf("operations[%d].value must be a string for tags", i))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// deepCopy clones JSON-shaped data so the original state is never modified.
func deepCopy(v any) any {
	raw, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(raw, &out)
	return out
}

func getPath(m map[string]any, segs []string) (any, bool) {
	var cur any = m
	for _, s := range segs {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[s]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// Apply returns the patched state and the field-level diff. Ops apply in
// order; values are normalised through JSON so 1 and 1.0 compare equal.
func Apply(s State, ops []Op) (State, []Change, error) {
	if err := ValidateOps(ops); err != nil {
		return State{}, nil, err
	}
	root := map[string]any{"configuration": deepCopy(orEmpty(s.Configuration)), "tags": deepCopy(orEmpty(s.Tags))}
	before := deepCopy(root).(map[string]any)
	for _, o := range ops {
		segs := strings.Split(o.Path, ".")
		parent := root
		for _, seg := range segs[:len(segs)-1] {
			next, ok := parent[seg].(map[string]any)
			if !ok {
				if o.Op == "remove" {
					parent = nil
					break
				}
				if _, exists := parent[seg]; exists {
					return State{}, nil, fmt.Errorf("%w: %s: %s is not an object", ErrInvalid, o.Path, seg)
				}
				next = map[string]any{}
				parent[seg] = next
			}
			parent = next
		}
		if parent == nil {
			continue
		}
		last := segs[len(segs)-1]
		if o.Op == "remove" {
			delete(parent, last)
		} else {
			parent[last] = deepCopy(o.Value)
		}
	}
	var diff []Change
	seen := map[string]bool{}
	for _, o := range ops {
		if seen[o.Path] {
			continue
		}
		seen[o.Path] = true
		segs := strings.Split(o.Path, ".")
		b, _ := getPath(before, segs)
		a, _ := getPath(root, segs)
		if !reflect.DeepEqual(a, b) {
			diff = append(diff, Change{Path: o.Path, Before: b, After: a})
		}
	}
	out := s
	out.Configuration = root["configuration"].(map[string]any)
	out.Tags = root["tags"].(map[string]any)
	return out, diff, nil
}

// Matches reports, for each op, whether the observed state now has the value
// the op set (or lacks the key it removed).
func Matches(observed State, ops []Op) (bool, []string) {
	root := map[string]any{"configuration": deepCopy(orEmpty(observed.Configuration)), "tags": deepCopy(orEmpty(observed.Tags))}
	var mismatched []string
	for _, o := range ops {
		got, ok := getPath(root, strings.Split(o.Path, "."))
		switch o.Op {
		case "remove":
			if ok {
				mismatched = append(mismatched, o.Path)
			}
		default:
			if !ok || !reflect.DeepEqual(got, deepCopy(o.Value)) {
				mismatched = append(mismatched, o.Path)
			}
		}
	}
	return len(mismatched) == 0, mismatched
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
