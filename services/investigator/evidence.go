// Package investigator is Module G: an evidence-grounded investigation
// assistant.
//
// Aegis works fully without it. The deterministic path collects evidence
// from Aegis's own records in a read-only transaction and writes a brief in
// which every sentence cites that evidence. An optional local model may add
// prose, but each model claim is checked against the cited evidence and
// rejected if it cites nothing, cites evidence that does not exist, contains
// a number or identifier that the cited evidence does not contain, or
// describes an action. The model has no tools: it cannot query, change or
// approve anything, and it is never the authority for a policy decision.
package investigator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/redact"
)

// Evidence is one fact Aegis recorded, with a pointer to where it came from.
// Summary is written by Aegis, never by a model.
type Evidence struct {
	ID      string         `json:"id"`     // E1, E2, ... in collection order
	Kind    string         `json:"kind"`   // resource, relationships, compliance_run, compliance_finding, exception, risk, drift, cost, recommendation
	Source  string         `json:"source"` // table/row the fact came from
	Summary string         `json:"summary"`
	Facts   map[string]any `json:"facts"`
}

// Bundle is the ordered evidence for one investigation.
type Bundle struct {
	Subject string     `json:"subject"`
	Account string     `json:"account"`
	Items   []Evidence `json:"items"`
}

func (b *Bundle) add(kind, source string, facts map[string]any, format string, args ...any) string {
	id := fmt.Sprintf("E%d", len(b.Items)+1)
	b.Items = append(b.Items, Evidence{ID: id, Kind: kind, Source: source, Summary: fmt.Sprintf(format, args...), Facts: facts})
	return id
}

// ByID indexes the bundle.
func (b Bundle) ByID() map[string]Evidence {
	m := make(map[string]Evidence, len(b.Items))
	for _, e := range b.Items {
		m[e.ID] = e
	}
	return m
}

// SHA256 is a digest of the canonical evidence JSON, stored with the
// investigation so a reviewer can tell exactly what the brief was based on.
func (b Bundle) SHA256() string {
	raw, _ := json.Marshal(b) // maps marshal with sorted keys: canonical
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// maxConfigBytes caps how much resource configuration goes into evidence.
const maxConfigBytes = 4096

// scrub redacts sensitive keys at any depth (defence in depth: inventory
// import already redacts) and returns a copy.
func scrub(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if redact.IsSensitiveKey(k) {
				out[k] = redact.Placeholder
				continue
			}
			out[k] = scrub(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = scrub(val)
		}
		return out
	default:
		return v
	}
}

// boundedConfig returns the scrubbed configuration, dropping keys
// (alphabetically last first) until it fits maxConfigBytes.
func boundedConfig(cfg map[string]any) (map[string]any, bool) {
	c, _ := scrub(cfg).(map[string]any)
	if c == nil {
		c = map[string]any{}
	}
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	truncated := false
	for len(keys) > 0 {
		raw, _ := json.Marshal(c)
		if len(raw) <= maxConfigBytes {
			break
		}
		last := keys[len(keys)-1]
		keys = keys[:len(keys)-1]
		delete(c, last)
		truncated = true
	}
	return c, truncated
}
