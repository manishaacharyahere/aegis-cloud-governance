// Package redact holds the single definition of which attribute names are
// treated as secrets, shared by every Aegis module that stores external data.
package redact

import "regexp"

// Placeholder replaces sensitive values.
const Placeholder = "[REDACTED]"

var sensitiveKey = regexp.MustCompile(`(?i)(password|passwd|secret|private_key|access_key|api_key|token|credential)`)

// IsSensitiveKey reports whether an attribute name suggests a secret value.
func IsSensitiveKey(k string) bool { return sensitiveKey.MatchString(k) }
