package remediation

import (
	"errors"
	"fmt"
	"sort"
)

// Template turns a failing rule into a proposed patch. Templates only
// propose: whether the patch actually fixes the rule is decided by running
// the policies on the patched state, so a wrong template is blocked, not
// released.
type Template struct {
	RuleID     string `json:"rule_id"`
	Title      string `json:"title"`
	Disruptive bool   `json:"disruptive"` // needs an extra approval
	Note       string `json:"note"`       // operational consequence a reviewer must weigh
	build      func(State) ([]Op, error)
}

// ErrNoTemplate means the rule needs a human-designed (manual) remediation.
var ErrNoTemplate = errors.New("no automatic remediation for this rule; submit a manual remediation")

func set(path string, v any) Op { return Op{Op: "set", Path: path, Value: v} }

var templates = map[string]Template{
	"AEGIS-S3-001": {Title: "Enable the S3 public access block",
		Note:  "Anonymous and cross-account public readers lose access; confirm no consumer relies on public reads.",
		build: func(State) ([]Op, error) { return []Op{set("configuration.public_access_block", true)}, nil }},
	"AEGIS-ENC-001": {Title: "Set default server-side encryption to aws:kms",
		Note:  "Applies to new objects; existing objects keep their encryption until rewritten. KMS requests are billed.",
		build: func(State) ([]Op, error) { return []Op{set("configuration.encryption", "aws:kms")}, nil }},
	"AEGIS-S3-002": {Title: "Enable bucket versioning",
		Note:  "Overwritten and deleted objects are retained, which increases storage cost unless a lifecycle rule expires old versions.",
		build: func(State) ([]Op, error) { return []Op{set("configuration.versioning", true)}, nil }},
	"AEGIS-DB-001": {Title: "Encrypt database storage at rest", Disruptive: true,
		Note:  "An existing RDS instance cannot be encrypted in place: snapshot, copy the snapshot with encryption, restore and cut over (downtime).",
		build: func(State) ([]Op, error) { return []Op{set("configuration.storage_encrypted", true)}, nil }},
	"AEGIS-DB-002": {Title: "Make the database private",
		Note:  "Clients outside the VPC lose access; check every reader listed under impact.",
		build: func(State) ([]Op, error) { return []Op{set("configuration.publicly_accessible", false)}, nil }},
	"AEGIS-NET-001": {Title: "Remove 0.0.0.0/0 from administrative-port ingress",
		Note:  "Administrative access from the internet stops; use a bastion host or SSM Session Manager.",
		build: func(s State) ([]Op, error) { return closeAdminIngress(s, "cidr_blocks", "0.0.0.0/0") }},
	"AEGIS-NET-002": {Title: "Remove ::/0 from administrative-port ingress",
		Note:  "Administrative access from the IPv6 internet stops; use a bastion host or SSM Session Manager.",
		build: func(s State) ([]Op, error) { return closeAdminIngress(s, "ipv6_cidr_blocks", "::/0") }},
	"AEGIS-LOG-001": {Title: "Enable CloudTrail logging and log file validation",
		Note: "CloudTrail delivery and storage are billed.",
		build: func(State) ([]Op, error) {
			return []Op{set("configuration.enable_logging", true), set("configuration.log_file_validation", true)}, nil
		}},
}

func init() {
	for id, t := range templates {
		t.RuleID = id
		templates[id] = t
	}
}

// Templates lists the rules with automatic remediations, sorted by rule ID.
func Templates() []Template {
	out := make([]Template, 0, len(templates))
	for _, t := range templates {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// FromTemplate returns the template and the ops it proposes for this state.
func FromTemplate(ruleID string, s State) (Template, []Op, error) {
	t, ok := templates[ruleID]
	if !ok {
		return Template{}, nil, fmt.Errorf("%w (%s)", ErrNoTemplate, ruleID)
	}
	ops, err := t.build(s)
	return t, ops, err
}

var adminPorts = []float64{22, 3389}

func coversAdminPort(rule map[string]any) bool {
	proto, _ := rule["protocol"].(string)
	if proto == "-1" || proto == "all" {
		return true
	}
	if proto != "tcp" && proto != "6" {
		return false
	}
	from, ok1 := rule["from_port"].(float64)
	to, ok2 := rule["to_port"].(float64)
	if !ok1 || !ok2 {
		return false
	}
	for _, p := range adminPorts {
		if from <= p && p <= to {
			return true
		}
	}
	return false
}

// closeAdminIngress removes the open CIDR from every ingress rule that
// covers an administrative port, and drops rules left with no source.
func closeAdminIngress(s State, field, cidr string) ([]Op, error) {
	ingress, _ := deepCopy(s.Configuration["ingress"]).([]any)
	if len(ingress) == 0 {
		return nil, fmt.Errorf("%w: security group has no ingress rules", ErrInvalid)
	}
	out := make([]any, 0, len(ingress))
	changed := false
	for _, r := range ingress {
		rule, ok := r.(map[string]any)
		if !ok {
			out = append(out, r)
			continue
		}
		if coversAdminPort(rule) {
			cidrs, _ := rule[field].([]any)
			kept := make([]any, 0, len(cidrs))
			for _, c := range cidrs {
				if c == cidr {
					changed = true
					continue
				}
				kept = append(kept, c)
			}
			rule[field] = kept
			v4, _ := rule["cidr_blocks"].([]any)
			v6, _ := rule["ipv6_cidr_blocks"].([]any)
			if len(v4)+len(v6) == 0 {
				continue // no source left: drop the rule
			}
		}
		out = append(out, rule)
	}
	if !changed {
		return nil, fmt.Errorf("%w: no administrative-port ingress from %s found", ErrInvalid, cidr)
	}
	return []Op{set("configuration.ingress", out)}, nil
}
