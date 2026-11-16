// Package inventory implements Module A (Cloud Asset Intelligence): it
// validates and normalises cloud inventory snapshots, computes changes against
// the previously observed state, and persists versioned resource history.
package inventory

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SchemaV1 is the only accepted snapshot contract version.
const SchemaV1 = "aegis.inventory/v1"

// Limits protect the importer from oversized or abusive input.
const (
	MaxResources     = 50_000
	MaxResourceIDLen = 512
	MaxTags          = 50
	MaxTagKeyLen     = 128
	MaxTagValueLen   = 256
	// Hub resources (KMS keys, VPCs, subnets, roles) legitimately have
	// hundreds of edges; the per-snapshot cap bounds total work instead.
	MaxRelationships     = 10_000
	MaxRelationshipsSum  = 500_000
	MaxConfigDepth       = 10
	clockSkewAllowance   = 5 * time.Minute
	maxReportedIssues    = 100
	maxAccountNameLength = 200
)

// Sources an import may come from.
var validSources = map[string]bool{
	"synthetic":       true,
	"terraform_state": true,
	"terraform_plan":  true,
	"aws":             true,
}

// Relationship types understood by the risk and drift engines.
var validRelationships = map[string]bool{
	"attached_to": true, // e.g. security group -> instance
	"member_of":   true, // e.g. subnet -> vpc
	"routes_to":   true, // e.g. load balancer -> instance
	"reads_from":  true,
	"writes_to":   true,
	"assumes":     true, // e.g. instance -> IAM role
	"encrypts":    true, // e.g. KMS key -> bucket
	"logs_to":     true,
	"depends_on":  true,
}

var (
	awsAccountID = regexp.MustCompile(`^[0-9]{12}$`)
	awsRegion    = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	printable    = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// Snapshot is the inventory import contract (aegis.inventory/v1).
type Snapshot struct {
	SchemaVersion string     `json:"schema_version"`
	Source        string     `json:"source"`
	CapturedAt    time.Time  `json:"captured_at"`
	Account       Account    `json:"account"`
	Resources     []Resource `json:"resources"`
}

// Account identifies the cloud account the snapshot was taken from.
type Account struct {
	Provider   string `json:"provider"`
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
}

// Resource is one observed infrastructure resource.
type Resource struct {
	ResourceID    string            `json:"resource_id"`
	ResourceType  string            `json:"resource_type"`
	Region        string            `json:"region,omitempty"`
	Environment   string            `json:"environment,omitempty"`
	Owner         string            `json:"owner,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
	Configuration map[string]any    `json:"configuration,omitempty"`
	Relationships []Relationship    `json:"relationships,omitempty"`
}

// Relationship is a directed edge from the containing resource to TargetID.
type Relationship struct {
	Type     string `json:"type"`
	TargetID string `json:"target_id"`
}

// Issue is one validation problem, addressed by a JSON-path-like location.
type Issue struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ValidationError reports every problem found in a snapshot (capped).
type ValidationError struct {
	Issues    []Issue
	Truncated bool
}

func (e *ValidationError) Error() string {
	if len(e.Issues) == 0 {
		return "invalid snapshot"
	}
	return fmt.Sprintf("invalid snapshot: %s: %s (and %d more)", e.Issues[0].Path, e.Issues[0].Message, len(e.Issues)-1)
}

func (e *ValidationError) add(path, format string, args ...any) {
	if len(e.Issues) >= maxReportedIssues {
		e.Truncated = true
		return
	}
	e.Issues = append(e.Issues, Issue{Path: path, Message: fmt.Sprintf(format, args...)})
}

// Validate checks the snapshot contract. now is injected for testability.
// It returns *ValidationError when the snapshot is rejected.
func Validate(s Snapshot, now time.Time) error {
	v := &ValidationError{}

	if s.SchemaVersion != SchemaV1 {
		v.add("schema_version", "must be %q", SchemaV1)
	}
	if !validSources[s.Source] {
		v.add("source", "unsupported source %q", s.Source)
	}
	switch {
	case s.CapturedAt.IsZero():
		v.add("captured_at", "required")
	case s.CapturedAt.After(now.Add(clockSkewAllowance)):
		v.add("captured_at", "is in the future")
	}

	if s.Account.Provider != "aws" {
		v.add("account.provider", "unsupported provider %q (only aws)", s.Account.Provider)
	} else if !awsAccountID.MatchString(s.Account.ExternalID) {
		v.add("account.external_id", "must be a 12-digit AWS account ID")
	}
	if n := len(strings.TrimSpace(s.Account.Name)); n == 0 || n > maxAccountNameLength {
		v.add("account.name", "must be 1-%d characters", maxAccountNameLength)
	}

	if len(s.Resources) > MaxResources {
		v.add("resources", "too many resources (%d > %d)", len(s.Resources), MaxResources)
		return v // do not iterate an abusive payload
	}

	seen := make(map[string]int, len(s.Resources))
	edges := 0
	for _, r := range s.Resources {
		edges += len(r.Relationships)
	}
	if edges > MaxRelationshipsSum {
		v.add("resources", "too many relationships in the snapshot (%d > %d)", edges, MaxRelationshipsSum)
	}
	for i, r := range s.Resources {
		p := fmt.Sprintf("resources[%d]", i)
		switch {
		case r.ResourceID == "":
			v.add(p+".resource_id", "required")
		case len(r.ResourceID) > MaxResourceIDLen || !printable.MatchString(r.ResourceID):
			v.add(p+".resource_id", "must be 1-%d printable non-space ASCII characters", MaxResourceIDLen)
		default:
			if first, dup := seen[r.ResourceID]; dup {
				v.add(p+".resource_id", "duplicate of resources[%d]", first)
			} else {
				seen[r.ResourceID] = i
			}
		}
		if strings.TrimSpace(r.ResourceType) == "" {
			v.add(p+".resource_type", "required")
		}
		if r.Region != "" && !awsRegion.MatchString(r.Region) {
			v.add(p+".region", "invalid region %q", r.Region)
		}
		if len(r.Tags) > MaxTags {
			v.add(p+".tags", "too many tags (%d > %d)", len(r.Tags), MaxTags)
		}
		for k, val := range r.Tags {
			if k == "" || len(k) > MaxTagKeyLen {
				v.add(p+".tags", "tag key must be 1-%d characters", MaxTagKeyLen)
			}
			if len(val) > MaxTagValueLen {
				v.add(p+".tags."+k, "tag value longer than %d characters", MaxTagValueLen)
			}
		}
		if depth(r.Configuration, 0) > MaxConfigDepth {
			v.add(p+".configuration", "nested deeper than %d levels", MaxConfigDepth)
		}
		if len(r.Relationships) > MaxRelationships {
			v.add(p+".relationships", "too many relationships (%d > %d)", len(r.Relationships), MaxRelationships)
		}
		for j, rel := range r.Relationships {
			rp := fmt.Sprintf("%s.relationships[%d]", p, j)
			if !validRelationships[rel.Type] {
				v.add(rp+".type", "unknown relationship type %q", rel.Type)
			}
			if rel.TargetID == "" {
				v.add(rp+".target_id", "required")
			} else if rel.TargetID == r.ResourceID {
				v.add(rp+".target_id", "self-referencing relationship")
			}
		}
	}

	if len(v.Issues) > 0 {
		return v
	}
	return nil
}

func depth(v any, d int) int {
	if d > MaxConfigDepth {
		return d
	}
	max := d
	switch t := v.(type) {
	case map[string]any:
		for _, c := range t {
			if n := depth(c, d+1); n > max {
				max = n
			}
		}
	case []any:
		for _, c := range t {
			if n := depth(c, d+1); n > max {
				max = n
			}
		}
	}
	return max
}

// Sentinel errors returned by the store and service.
var (
	ErrTenantNotFound = errors.New("tenant not found")
	ErrStaleSnapshot  = errors.New("snapshot is older than the latest import for this account")
	ErrNotFound       = errors.New("not found")
)
