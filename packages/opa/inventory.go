package opa

import (
	"context"
	"fmt"
	"sort"
)

// Resource is one resource as the inventory policies read it: the
// input.resources[] contract of policies/aws/inventory.rego, defined once.
// Compliance, drift and the remediation simulation all evaluate through it,
// so a field added to the policies is added in one place; a field missing
// from one caller's copy would have silently meant "no finding".
type Resource struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	Region        string         `json:"region"`
	Tags          map[string]any `json:"tags"`
	Configuration map[string]any `json:"configuration"`
}

// Finding is one deny or warn result of the inventory policies.
type Finding struct {
	RuleID  string `json:"rule_id"`
	Address string `json:"address"` // the resource ID
	Message string `json:"message"`
}

// Querier is what policy evaluation needs from OPA: the Client in
// production, a fake in unit tests.
type Querier interface {
	Query(ctx context.Context, path string, input any, out any) error
	Bundle(ctx context.Context) (Bundle, error)
}

var _ Querier = (*Client)(nil)

// EvaluateInventory runs the inventory policies (deny and warn) over the
// resources, ChunkSize at a time, with the tenant's policy configuration.
func EvaluateInventory(ctx context.Context, q Querier, resources []Resource, config map[string]any) ([]Finding, error) {
	var out []Finding
	for _, chunk := range Chunks(resources, ChunkSize) {
		var res struct {
			Deny []Finding `json:"deny"`
			Warn []Finding `json:"warn"`
		}
		if err := q.Query(ctx, "aegis.inventory", map[string]any{"resources": chunk, "config": config}, &res); err != nil {
			return nil, fmt.Errorf("evaluate inventory policies: %w", err)
		}
		out = append(out, res.Deny...)
		out = append(out, res.Warn...)
	}
	return out, nil
}

// FailingRules groups findings by resource: resource ID -> sorted, unique rule IDs.
func FailingRules(findings []Finding) map[string][]string {
	sets := map[string]map[string]bool{}
	for _, f := range findings {
		if sets[f.Address] == nil {
			sets[f.Address] = map[string]bool{}
		}
		sets[f.Address][f.RuleID] = true
	}
	out := make(map[string][]string, len(sets))
	for addr, set := range sets {
		ids := make([]string, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out[addr] = ids
	}
	return out
}
