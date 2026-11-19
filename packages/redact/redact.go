// Package redact holds the single definition of which attribute names are
// treated as secrets, shared by every Aegis module that stores external data.
package redact

import (
	"regexp"
	"sort"
)

// Placeholder replaces sensitive values.
const Placeholder = "[REDACTED]"

var sensitiveKey = regexp.MustCompile(`(?i)(password|passwd|secret|private_key|access_key|api_key|token|credential)`)

// IsSensitiveKey reports whether an attribute name suggests a secret value.
func IsSensitiveKey(k string) bool { return sensitiveKey.MatchString(k) }

// ShouldRedact reports whether the value v stored under key k must be
// replaced: the key looks secret and the value could hold one. nil, "" and
// booleans cannot (manage_master_user_password = true is a setting, not a
// secret, and policies read it), so they are kept.
func ShouldRedact(k string, v any) bool {
	if !IsSensitiveKey(k) || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return false
	case string:
		return t != ""
	}
	return true
}

// Walk returns a deep copy of v with every value ShouldRedact selects
// replaced by Placeholder, at any depth (maps and lists). The dotted path of
// each replaced value is appended to paths when paths is not nil; keys are
// visited in sorted order, so the paths are deterministic. A nil map comes
// back as an empty map, so content hashes are stable.
//
// It is the one redaction walk shared by inventory import, Terraform plan
// analysis and the investigator's evidence.
func Walk(v any, path string, paths *[]string) any {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]any, len(t))
		for _, k := range keys {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if ShouldRedact(k, t[k]) {
				if paths != nil {
					*paths = append(*paths, p)
				}
				out[k] = Placeholder
				continue
			}
			out[k] = Walk(t[k], p, paths)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = Walk(e, path, paths)
		}
		return out
	default:
		return v
	}
}
