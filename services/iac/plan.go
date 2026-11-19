// Package iac implements Module B (Terraform and IaC intelligence): it turns
// a Terraform plan into a redacted, structured description of planned
// changes, evaluates it with OPA, runs Trivy and Checkov, and merges all
// results into one report.
package iac

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/redact"
)

// MaxPlanBytes bounds the plan JSON the parser will read.
const MaxPlanBytes = 64 << 20

// Plan is the subset of `terraform show -json` output Aegis relies on.
// Fields that commonly contain secrets (prior_state, output values) are
// deliberately not modelled. Root variables are read only to resolve a
// provider region given as `var.<name>`; they are never retained.
type Plan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
	Configuration    struct {
		ProviderConfig map[string]ProviderConfig `json:"provider_config"`
		RootModule     ConfigModule              `json:"root_module"`
	} `json:"configuration"`
	Variables map[string]struct {
		Value any `json:"value"`
	} `json:"variables"`
	Errored bool `json:"errored"`
}

// ResourceChange is one entry of resource_changes.
type ResourceChange struct {
	Address       string `json:"address"`
	ModuleAddress string `json:"module_address"`
	Mode          string `json:"mode"`
	Type          string `json:"type"`
	Name          string `json:"name"`
	Change        struct {
		Actions         []string `json:"actions"`
		Before          any      `json:"before"`
		After           any      `json:"after"`
		AfterUnknown    any      `json:"after_unknown"`
		BeforeSensitive any      `json:"before_sensitive"`
		AfterSensitive  any      `json:"after_sensitive"`
	} `json:"change"`
}

// ProviderConfig is a provider block from the configuration section.
type ProviderConfig struct {
	Name        string                     `json:"name"`
	Expressions map[string]json.RawMessage `json:"expressions"`
}

// ConfigModule is a module in the configuration section.
type ConfigModule struct {
	Resources   []ConfigResource `json:"resources"`
	ModuleCalls map[string]struct {
		Source string       `json:"source"`
		Module ConfigModule `json:"module"`
	} `json:"module_calls"`
}

// ConfigResource is a resource block in the configuration section.
type ConfigResource struct {
	Address           string                     `json:"address"`
	Type              string                     `json:"type"`
	ProviderConfigKey string                     `json:"provider_config_key"`
	Expressions       map[string]json.RawMessage `json:"expressions"`
}

// ParsePlan decodes and sanity-checks plan JSON.
func ParsePlan(r io.Reader) (*Plan, error) {
	var p Plan
	dec := json.NewDecoder(io.LimitReader(r, MaxPlanBytes+1))
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode plan: %w", err)
	}
	if !strings.HasPrefix(p.FormatVersion, "1.") {
		return nil, fmt.Errorf("unsupported plan format_version %q (want 1.x)", p.FormatVersion)
	}
	if p.Errored {
		return nil, errors.New("plan is marked as errored")
	}
	return &p, nil
}

// Action is the planned operation on a resource.
type Action string

const (
	ActionCreate  Action = "create"
	ActionUpdate  Action = "update"
	ActionDelete  Action = "delete"
	ActionReplace Action = "replace"
	ActionRead    Action = "read"
	ActionNoOp    Action = "no-op"
)

func classify(actions []string) Action {
	switch strings.Join(actions, ",") {
	case "create":
		return ActionCreate
	case "update":
		return ActionUpdate
	case "delete":
		return ActionDelete
	case "delete,create", "create,delete":
		return ActionReplace
	case "read":
		return ActionRead
	default:
		return ActionNoOp
	}
}

// PlannedResource is the redacted, enriched view of one planned change. It is
// both the OPA policy input and what Aegis stores.
type PlannedResource struct {
	Address     string                    `json:"address"`
	Type        string                    `json:"type"`
	Name        string                    `json:"name"`
	Module      string                    `json:"module,omitempty"`
	Action      Action                    `json:"action"`
	Actions     []string                  `json:"actions"`
	Destructive bool                      `json:"destructive"`
	Region      string                    `json:"region,omitempty"`
	Taggable    bool                      `json:"taggable"`
	Tags        map[string]string         `json:"tags"`
	Before      map[string]any            `json:"before,omitempty"`
	After       map[string]any            `json:"after,omitempty"`
	Linked      map[string]map[string]any `json:"linked,omitempty"`
}

// Summary counts planned actions.
type Summary struct {
	Create  int `json:"create"`
	Update  int `json:"update"`
	Delete  int `json:"delete"`
	Replace int `json:"replace"`
	Read    int `json:"read"`
	NoOp    int `json:"no_op"`
}

// Analysis is the result of analysing a plan.
type Analysis struct {
	TerraformVersion string            `json:"terraform_version"`
	Resources        []PlannedResource `json:"resources"`
	Summary          Summary           `json:"summary"`
	RedactedPaths    []string          `json:"redacted_paths"`
}

// s3Companions are resources that configure an aws_s3_bucket through a
// `bucket` reference (AWS provider v4+ split the bucket resource).
var s3Companions = map[string]bool{
	"aws_s3_bucket_public_access_block":                  true,
	"aws_s3_bucket_server_side_encryption_configuration": true,
	"aws_s3_bucket_versioning":                           true,
	"aws_s3_bucket_policy":                               true,
	"aws_s3_bucket_acl":                                  true,
	"aws_s3_bucket_logging":                              true,
}

// Analyze converts a parsed plan into planned resources. It never returns
// unredacted sensitive values.
func Analyze(p *Plan) Analysis {
	a := Analysis{TerraformVersion: p.TerraformVersion, RedactedPaths: []string{}}
	cfg := indexConfig(p)

	byAddr := map[string]*PlannedResource{}
	var order []string
	for _, rc := range p.ResourceChanges {
		if rc.Mode != "" && rc.Mode != "managed" {
			continue // data sources are not infrastructure changes
		}
		action := classify(rc.Change.Actions)
		pr := &PlannedResource{
			Address: rc.Address, Type: rc.Type, Name: rc.Name, Module: rc.ModuleAddress,
			Action: action, Actions: rc.Change.Actions,
			Destructive: action == ActionDelete || action == ActionReplace,
		}
		var paths []string
		pr.Before = redactValue(rc.Change.Before, rc.Change.BeforeSensitive, rc.Address+".before", &paths)
		pr.After = redactValue(rc.Change.After, rc.Change.AfterSensitive, rc.Address+".after", &paths)
		a.RedactedPaths = append(a.RedactedPaths, paths...)

		c := cfg[rc.Address]
		prov := p.Configuration.ProviderConfig[c.providerKey]
		pr.Region = p.resolveString(prov.Expressions["region"])

		pr.Taggable, pr.Tags = effectiveTags(pr.After, rc.Change.AfterUnknown, defaultTags(prov))

		switch action {
		case ActionCreate:
			a.Summary.Create++
		case ActionUpdate:
			a.Summary.Update++
		case ActionDelete:
			a.Summary.Delete++
		case ActionReplace:
			a.Summary.Replace++
		case ActionRead:
			a.Summary.Read++
		default:
			a.Summary.NoOp++
		}
		byAddr[rc.Address] = pr
		order = append(order, rc.Address)
	}

	// Attach S3 companion configuration to the bucket it references.
	for _, addr := range order {
		pr := byAddr[addr]
		if !s3Companions[pr.Type] || pr.Action == ActionDelete {
			continue
		}
		target := cfg[addr].bucketRef
		if target == "" {
			continue
		}
		if b, ok := byAddr[target]; ok && b.Type == "aws_s3_bucket" {
			if b.Linked == nil {
				b.Linked = map[string]map[string]any{}
			}
			b.Linked[pr.Type] = pr.After
		}
	}

	sort.Strings(order)
	for _, addr := range order {
		a.Resources = append(a.Resources, *byAddr[addr])
	}
	sort.Strings(a.RedactedPaths)
	return a
}

type configInfo struct {
	providerKey string
	bucketRef   string // resolved address of a referenced aws_s3_bucket
}

// indexConfig maps full resource addresses to configuration details,
// walking nested module calls.
func indexConfig(p *Plan) map[string]configInfo {
	out := map[string]configInfo{}
	var walk func(m ConfigModule, prefix string)
	walk = func(m ConfigModule, prefix string) {
		for _, r := range m.Resources {
			info := configInfo{providerKey: r.ProviderConfigKey}
			if raw, ok := r.Expressions["bucket"]; ok {
				var e struct {
					References []string `json:"references"`
				}
				if json.Unmarshal(raw, &e) == nil {
					for _, ref := range e.References {
						if strings.HasPrefix(ref, "aws_s3_bucket.") && strings.Count(ref, ".") == 1 {
							info.bucketRef = prefix + ref
							break
						}
					}
				}
			}
			out[prefix+r.Address] = info
		}
		names := make([]string, 0, len(m.ModuleCalls))
		for n := range m.ModuleCalls {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			walk(m.ModuleCalls[n].Module, prefix+"module."+n+".")
		}
	}
	walk(p.Configuration.RootModule, "")
	return out
}

// resolveString returns a literal string expression, or the value of a root
// variable when the expression is exactly `var.<name>`. Anything else (locals,
// module inputs, functions) is "", which the region policy reports as unknown.
func (p *Plan) resolveString(raw json.RawMessage) string {
	if s := constantString(raw); s != "" {
		return s
	}
	var e struct {
		References []string `json:"references"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &e) != nil || len(e.References) != 1 {
		return ""
	}
	name, ok := strings.CutPrefix(e.References[0], "var.")
	if !ok {
		return ""
	}
	s, _ := p.Variables[name].Value.(string)
	return s
}

func constantString(raw json.RawMessage) string {
	var e struct {
		ConstantValue any `json:"constant_value"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &e) != nil {
		return ""
	}
	s, _ := e.ConstantValue.(string)
	return s
}

func defaultTags(prov ProviderConfig) map[string]string {
	raw, ok := prov.Expressions["default_tags"]
	if !ok {
		return nil
	}
	var blocks []struct {
		Tags struct {
			ConstantValue map[string]any `json:"constant_value"`
		} `json:"tags"`
	}
	if json.Unmarshal(raw, &blocks) != nil || len(blocks) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range blocks[0].Tags.ConstantValue {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// effectiveTags returns whether the resource supports tags and the tags it
// will carry after apply: tags_all when known, otherwise provider default
// tags merged with the resource's own tags.
func effectiveTags(after map[string]any, afterUnknown any, defaults map[string]string) (bool, map[string]string) {
	out := map[string]string{}
	if after == nil {
		return false, out
	}
	_, hasTags := after["tags"]
	_, hasTagsAll := after["tags_all"]
	if !hasTags && !hasTagsAll && !unknownKey(afterUnknown, "tags_all") {
		return false, out
	}
	if all, ok := after["tags_all"].(map[string]any); ok && len(all) > 0 {
		for k, v := range all {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
		return true, out
	}
	for k, v := range defaults {
		out[k] = v
	}
	if own, ok := after["tags"].(map[string]any); ok {
		for k, v := range own {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
	}
	return true, out
}

func unknownKey(unknown any, key string) bool {
	m, ok := unknown.(map[string]any)
	if !ok {
		return false
	}
	_, present := m[key]
	return present
}

// redactValue deep-copies v as a map, replacing values that Terraform marks
// sensitive (via the parallel sensitive mask) or whose key looks secret.
func redactValue(v, mask any, path string, paths *[]string) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out, _ := redactAny(m, mask, path, paths).(map[string]any)
	return out
}

func redactAny(v, mask any, path string, paths *[]string) any {
	if b, ok := mask.(bool); ok && b && v != nil {
		*paths = append(*paths, path)
		return redact.Placeholder
	}
	switch t := v.(type) {
	case map[string]any:
		mm, _ := mask.(map[string]any)
		out := make(map[string]any, len(t))
		for k, x := range t {
			p := path + "." + k
			if redact.IsSensitiveKey(k) && x != nil && x != "" {
				if _, isBool := x.(bool); !isBool {
					*paths = append(*paths, p)
					out[k] = redact.Placeholder
					continue
				}
			}
			out[k] = redactAny(x, mm[k], p, paths)
		}
		return out
	case []any:
		ml, _ := mask.([]any)
		out := make([]any, len(t))
		for i, x := range t {
			var sub any
			if i < len(ml) {
				sub = ml[i]
			}
			out[i] = redactAny(x, sub, fmt.Sprintf("%s[%d]", path, i), paths)
		}
		return out
	default:
		return v
	}
}
