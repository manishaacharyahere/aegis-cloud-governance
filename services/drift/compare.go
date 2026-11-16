// Package drift implements Module D: it compares the observed inventory with
// the last approved baseline and classifies every difference.
//
// Comparison never uses raw JSON strings. Both sides are flattened into
// canonical leaf paths, provider defaults are filled in, volatile fields are
// ignored and order-insensitive lists are compared as sorted multisets.
package drift

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

// Categories, in priority order (highest first).
const (
	CategorySecurity      = "security"
	CategoryDeleted       = "deleted"
	CategoryUnmanaged     = "unmanaged"
	CategoryCost          = "cost"
	CategoryConfiguration = "configuration"
	CategoryTagging       = "tagging"
)

var categoryRank = map[string]int{
	CategorySecurity: 0, CategoryDeleted: 1, CategoryUnmanaged: 2,
	CategoryCost: 3, CategoryConfiguration: 4, CategoryTagging: 5,
}

// State is one resource as approved or as observed.
type State struct {
	ResourceID    string            `json:"resource_id"`
	Type          string            `json:"resource_type"`
	Region        string            `json:"region"`
	Environment   string            `json:"environment"`
	Owner         string            `json:"owner"`
	Tags          map[string]string `json:"tags"`
	Configuration map[string]any    `json:"configuration"`
}

// Config controls canonicalisation and classification.
type Config struct {
	// Ignore lists volatile paths; a trailing ".*" ignores a whole subtree.
	Ignore []string `json:"ignore"`
	// Defaults are provider defaults per resource type: a missing path is
	// treated as having this value, so "absent" and "default" never drift.
	Defaults map[string]map[string]any `json:"defaults"`
	// Unordered lists are compared as sorted multisets.
	Unordered []string `json:"unordered"`
	// Security and Cost paths per resource type ("*" = any type).
	Security map[string][]string `json:"security"`
	Cost     map[string][]string `json:"cost"`
	// StatefulTypes make deletions high severity.
	StatefulTypes []string `json:"stateful_types"`
}

// DefaultConfig is the configuration Aegis ships with.
func DefaultConfig() Config {
	return Config{
		Ignore: []string{"tags.last_scanned", "tags.aegis_*", "configuration.last_modified", "configuration.metadata.*"},
		Defaults: map[string]map[string]any{
			"storage.bucket":         {"configuration.versioning": false, "configuration.public_access_block": false},
			"database.instance":      {"configuration.publicly_accessible": false, "configuration.multi_az": false},
			"compute.instance":       {"configuration.monitoring": false},
			"network.security_group": {"configuration.ingress": []any{}},
		},
		Unordered: []string{"configuration.ingress", "configuration.statements", "configuration.cidr_blocks"},
		Security: map[string][]string{
			"storage.bucket":         {"configuration.public_access_block", "configuration.encryption"},
			"database.instance":      {"configuration.publicly_accessible", "configuration.storage_encrypted"},
			"network.security_group": {"configuration.ingress"},
			"identity.policy":        {"configuration.statements"},
			"identity.role":          {"configuration.assume_role_service"},
			"logging.trail":          {"configuration.enable_logging", "configuration.log_file_validation"},
			"compute.instance":       {"configuration.imdsv2_required", "configuration.ebs_encrypted"},
			"*":                      {"region"},
		},
		Cost: map[string][]string{
			"compute.instance":  {"configuration.instance_type"},
			"database.instance": {"configuration.instance_class", "configuration.allocated_storage", "configuration.multi_az"},
		},
		StatefulTypes: []string{"storage.bucket", "database.instance", "security.kms_key"},
	}
}

// SHA256 identifies a configuration so reports record how they were produced.
func (c Config) SHA256() string {
	b, _ := json.Marshal(c)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// PathChange is one differing canonical path.
type PathChange struct {
	Path     string `json:"path"`
	Category string `json:"category"`
	Before   any    `json:"before"`
	After    any    `json:"after"`
}

// Item is the drift of one resource.
type Item struct {
	ResourceID   string       `json:"resource_id"`
	ResourceType string       `json:"resource_type"`
	Category     string       `json:"category"`
	Severity     string       `json:"severity"`
	Changes      []PathChange `json:"changes,omitempty"`
	NewFailures  []string     `json:"new_failures,omitempty"` // rules failing now but not in the baseline
	Resolved     []string     `json:"resolved,omitempty"`     // rules failing in the baseline but not now
}

// Flatten turns a state into canonical leaf paths. Objects are walked into;
// arrays are leaves (sorted when listed as unordered). Values are canonical
// JSON, so 1, 1.0 and json.Number("1") compare equal and key order never matters.
func (c Config) Flatten(s State) map[string]string {
	out := map[string]string{}
	put := func(path string, v any) {
		if c.ignored(path) {
			return
		}
		out[path] = canonical(v, c.isUnordered(path))
	}
	put("region", s.Region)
	put("environment", s.Environment)
	put("owner", s.Owner)
	for k, v := range s.Tags {
		put("tags."+k, v)
	}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		if m, ok := v.(map[string]any); ok && len(m) > 0 {
			for k, x := range m {
				walk(prefix+"."+k, x)
			}
			return
		}
		put(prefix, v)
	}
	for k, v := range s.Configuration {
		walk("configuration."+k, v)
	}
	for path, def := range c.Defaults[s.Type] {
		if _, ok := out[path]; !ok && !c.ignored(path) {
			out[path] = canonical(def, c.isUnordered(path))
		}
	}
	return out
}

func (c Config) ignored(path string) bool {
	for _, p := range c.Ignore {
		switch {
		case strings.HasSuffix(p, ".*") && strings.HasPrefix(path, strings.TrimSuffix(p, "*")):
			return true
		case strings.HasSuffix(p, "*") && !strings.HasSuffix(p, ".*") && strings.HasPrefix(path, strings.TrimSuffix(p, "*")):
			return true
		case p == path:
			return true
		}
	}
	return false
}

func (c Config) isUnordered(path string) bool {
	for _, p := range c.Unordered {
		if p == path {
			return true
		}
	}
	return false
}

// canonical returns a stable JSON encoding. Numbers are normalised through
// float64; unordered arrays are sorted by their elements' canonical form.
func canonical(v any, unordered bool) string {
	norm := normalise(v)
	if arr, ok := norm.([]any); ok && unordered {
		parts := make([]string, len(arr))
		for i, e := range arr {
			parts[i] = canonical(e, false)
		}
		sort.Strings(parts)
		return "[" + strings.Join(parts, ",") + "]"
	}
	b, _ := json.Marshal(norm)
	return string(b)
}

func normalise(v any) any {
	switch t := v.(type) {
	case json.Number:
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[k] = normalise(x)
		}
		return m
	case []any:
		s := make([]any, len(t))
		for i, x := range t {
			s[i] = normalise(x)
		}
		return s
	default:
		return v
	}
}

func (c Config) categorise(typ, path string) string {
	if strings.HasPrefix(path, "tags.") || path == "owner" || path == "environment" {
		return CategoryTagging
	}
	for _, key := range []string{typ, "*"} {
		for _, p := range c.Security[key] {
			if p == path || strings.HasPrefix(path, p+".") {
				return CategorySecurity
			}
		}
		for _, p := range c.Cost[key] {
			if p == path || strings.HasPrefix(path, p+".") {
				return CategoryCost
			}
		}
	}
	return CategoryConfiguration
}

// Compare diffs approved against observed. failures maps resource ID to the
// policy rules failing on it, for each side; newly failing rules raise the
// item to security drift with the rule's severity (ruleSeverity).
func Compare(cfg Config, approved, observed map[string]State,
	approvedFailures, observedFailures map[string][]string, ruleSeverity map[string]string) []Item {

	stateful := map[string]bool{}
	for _, t := range cfg.StatefulTypes {
		stateful[t] = true
	}
	var items []Item
	for id, a := range approved {
		if _, ok := observed[id]; !ok {
			sev := "medium"
			if stateful[a.Type] {
				sev = "high"
			}
			items = append(items, Item{ResourceID: id, ResourceType: a.Type, Category: CategoryDeleted, Severity: sev})
		}
	}
	for id, o := range observed {
		a, known := approved[id]
		newFail, resolved := ruleDelta(approvedFailures[id], observedFailures[id])
		if !known {
			it := Item{ResourceID: id, ResourceType: o.Type, Category: CategoryUnmanaged, Severity: "medium",
				NewFailures: observedFailures[id]}
			it.Severity = maxSeverity(it.Severity, observedFailures[id], ruleSeverity)
			items = append(items, it)
			continue
		}
		before, after := cfg.Flatten(a), cfg.Flatten(o)
		var changes []PathChange
		for _, p := range unionKeys(before, after) {
			if before[p] == after[p] {
				continue
			}
			changes = append(changes, PathChange{Path: p, Category: cfg.categorise(o.Type, p),
				Before: decodeOrNil(before[p]), After: decodeOrNil(after[p])})
		}
		if len(changes) == 0 && len(newFail) == 0 {
			continue
		}
		it := Item{ResourceID: id, ResourceType: o.Type, Changes: changes, NewFailures: newFail, Resolved: resolved,
			Category: CategoryTagging}
		for _, ch := range changes {
			if categoryRank[ch.Category] < categoryRank[it.Category] {
				it.Category = ch.Category
			}
		}
		if len(newFail) > 0 {
			it.Category = CategorySecurity
		}
		it.Severity = baseSeverity(it.Category)
		it.Severity = maxSeverity(it.Severity, newFail, ruleSeverity)
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool {
		if r := sevRank[items[i].Severity] - sevRank[items[j].Severity]; r != 0 {
			return r < 0
		}
		if r := categoryRank[items[i].Category] - categoryRank[items[j].Category]; r != 0 {
			return r < 0
		}
		return items[i].ResourceID < items[j].ResourceID
	})
	return items
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

func baseSeverity(category string) string {
	switch category {
	case CategorySecurity, CategoryCost:
		return "medium"
	default:
		return "low"
	}
}

func maxSeverity(cur string, rules []string, sev map[string]string) string {
	for _, r := range rules {
		if s, ok := sev[r]; ok && sevRank[s] < sevRank[cur] {
			cur = s
		}
	}
	return cur
}

func ruleDelta(before, after []string) (added, removed []string) {
	b, a := map[string]bool{}, map[string]bool{}
	for _, r := range before {
		b[r] = true
	}
	for _, r := range after {
		a[r] = true
	}
	for r := range a {
		if !b[r] {
			added = append(added, r)
		}
	}
	for r := range b {
		if !a[r] {
			removed = append(removed, r)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return
}

func unionKeys(a, b map[string]string) []string {
	set := map[string]bool{}
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func decodeOrNil(s string) any {
	if s == "" {
		return nil
	}
	var v any
	_ = json.Unmarshal([]byte(s), &v)
	return v
}
