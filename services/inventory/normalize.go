package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/redact"
)

// typeMap maps provider-native (Terraform) types to Aegis normalised types.
var typeMap = map[string]string{
	"aws_vpc":                  "network.vpc",
	"aws_subnet":               "network.subnet",
	"aws_security_group":       "network.security_group",
	"aws_lb":                   "network.load_balancer",
	"aws_instance":             "compute.instance",
	"aws_db_instance":          "database.instance",
	"aws_s3_bucket":            "storage.bucket",
	"aws_iam_role":             "identity.role",
	"aws_iam_policy":           "identity.policy",
	"aws_iam_user":             "identity.user",
	"aws_kms_key":              "security.kms_key",
	"aws_cloudtrail":           "logging.trail",
	"aws_cloudwatch_log_group": "logging.log_group",
}

var normalisedTypes = func() map[string]bool {
	m := map[string]bool{}
	for _, v := range typeMap {
		m[v] = true
	}
	return m
}()

var environmentAliases = map[string]string{
	"prod": "production", "prd": "production", "production": "production",
	"stage": "staging", "stg": "staging", "staging": "staging",
	"dev": "development", "development": "development",
	"test": "test", "qa": "test",
	"sandbox": "sandbox",
}

// RequiredTags must be present on every resource for ownership and cost
// allocation. Missing tags produce warnings, not rejections.
var RequiredTags = []string{"owner", "environment", "cost_center"}

// Redacted replaces sensitive configuration values.
const Redacted = redact.Placeholder

// Warning is a non-fatal data-quality observation about an import.
type Warning struct {
	ResourceID string `json:"resource_id,omitempty"`
	Code       string `json:"code"`
	Detail     string `json:"detail"`
}

// NormalizedResource is the canonical, provider-independent representation
// that is hashed, diffed and stored.
type NormalizedResource struct {
	ResourceID    string            `json:"resource_id"`
	ResourceType  string            `json:"resource_type"`
	NativeType    string            `json:"native_type"`
	Region        string            `json:"region"`
	Environment   string            `json:"environment"`
	Owner         string            `json:"owner"`
	Tags          map[string]string `json:"tags"`
	Configuration map[string]any    `json:"configuration"`
	Relationships []Relationship    `json:"relationships"`
	ContentSHA256 string            `json:"-"`
}

// NormalizedSnapshot is a validated, normalised snapshot ready to persist.
type NormalizedSnapshot struct {
	Snapshot  Snapshot
	Resources []NormalizedResource // sorted by ResourceID
	Warnings  []Warning
	SHA256    string // identity of the snapshot, independent of formatting and ordering
}

// Normalize converts a validated snapshot into canonical form. It is pure and
// deterministic: the same logical snapshot always yields the same hashes.
func Normalize(s Snapshot) NormalizedSnapshot {
	out := NormalizedSnapshot{Snapshot: s, Resources: make([]NormalizedResource, 0, len(s.Resources))}
	ids := make(map[string]bool, len(s.Resources))
	for _, r := range s.Resources {
		ids[r.ResourceID] = true
	}

	for _, r := range s.Resources {
		n := NormalizedResource{
			ResourceID: r.ResourceID,
			NativeType: strings.ToLower(strings.TrimSpace(r.ResourceType)),
			Region:     r.Region,
			Tags:       make(map[string]string, len(r.Tags)),
		}
		switch {
		case typeMap[n.NativeType] != "":
			n.ResourceType = typeMap[n.NativeType]
		case normalisedTypes[n.NativeType]:
			n.ResourceType = n.NativeType
		default:
			n.ResourceType = "other." + n.NativeType
			out.Warnings = append(out.Warnings, Warning{r.ResourceID, "unknown_resource_type", n.NativeType})
		}

		for k, v := range r.Tags {
			n.Tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}

		env := firstNonEmpty(r.Environment, n.Tags["environment"])
		if canon, ok := environmentAliases[strings.ToLower(env)]; ok {
			n.Environment = canon
		} else if env != "" {
			n.Environment = strings.ToLower(env)
			out.Warnings = append(out.Warnings, Warning{r.ResourceID, "unknown_environment", env})
		}
		n.Owner = firstNonEmpty(r.Owner, n.Tags["owner"])

		for _, t := range RequiredTags {
			if n.Tags[t] == "" {
				out.Warnings = append(out.Warnings, Warning{r.ResourceID, "missing_tag", t})
			}
		}

		var redacted []string
		n.Configuration = redactMap(r.Configuration, "", &redacted)
		for _, p := range redacted {
			out.Warnings = append(out.Warnings, Warning{r.ResourceID, "sensitive_attribute_redacted", p})
		}

		n.Relationships = dedupeRelationships(r.Relationships)
		for _, rel := range n.Relationships {
			if !ids[rel.TargetID] {
				out.Warnings = append(out.Warnings, Warning{r.ResourceID, "dangling_relationship", rel.Type + " -> " + rel.TargetID})
			}
		}

		n.ContentSHA256 = hashJSON(n)
		out.Resources = append(out.Resources, n)
	}

	sort.Slice(out.Resources, func(i, j int) bool { return out.Resources[i].ResourceID < out.Resources[j].ResourceID })

	h := sha256.New()
	writeField := func(s string) { h.Write([]byte(s)); h.Write([]byte{0}) }
	writeField(s.SchemaVersion)
	writeField(s.Source)
	writeField(s.CapturedAt.UTC().Format("2006-01-02T15:04:05.999999999Z"))
	writeField(s.Account.Provider)
	writeField(s.Account.ExternalID)
	for _, r := range out.Resources {
		writeField(r.ResourceID)
		writeField(r.ContentSHA256)
	}
	out.SHA256 = hex.EncodeToString(h.Sum(nil))
	return out
}

// redactMap returns a deep copy of cfg with sensitive values replaced, recording
// the redacted paths. Nil maps become empty maps so hashes are stable.
func redactMap(cfg map[string]any, prefix string, paths *[]string) map[string]any {
	out := make(map[string]any, len(cfg))
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		if redact.IsSensitiveKey(k) {
			if cfg[k] != nil {
				*paths = append(*paths, p)
				out[k] = Redacted
			} else {
				out[k] = nil
			}
			continue
		}
		out[k] = redactValue(cfg[k], p, paths)
	}
	return out
}

func redactValue(v any, path string, paths *[]string) any {
	switch t := v.(type) {
	case map[string]any:
		return redactMap(t, path, paths)
	case []any:
		cp := make([]any, len(t))
		for i, e := range t {
			cp[i] = redactValue(e, path, paths)
		}
		return cp
	default:
		return v
	}
}

func dedupeRelationships(in []Relationship) []Relationship {
	seen := map[Relationship]bool{}
	out := make([]Relationship, 0, len(in))
	for _, r := range in {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].TargetID < out[j].TargetID
	})
	return out
}

// hashJSON hashes the canonical JSON encoding. encoding/json sorts map keys,
// which makes the encoding deterministic.
func hashJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Only possible for unsupported types, which decoded JSON never contains.
		panic("inventory: canonical encoding failed: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}
