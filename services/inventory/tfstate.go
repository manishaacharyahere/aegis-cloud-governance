package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// StateOptions identify the account a Terraform state describes. The state
// file itself does not reliably say which account it belongs to.
type StateOptions struct {
	AccountID   string // 12-digit AWS account; empty: taken from the first ARN found
	AccountName string
	CapturedAt  time.Time // zero: now
	Environment string    // default for resources without an environment tag
}

// tfState is the subset of the Terraform state v4 format that is read.
type tfState struct {
	Version   int `json:"version"`
	Resources []struct {
		Module    string `json:"module"`
		Mode      string `json:"mode"`
		Type      string `json:"type"`
		Name      string `json:"name"`
		Provider  string `json:"provider"`
		Instances []struct {
			IndexKey            any             `json:"index_key"`
			Attributes          map[string]any  `json:"attributes"`
			SensitiveAttributes json.RawMessage `json:"sensitive_attributes"`
			Dependencies        []string        `json:"dependencies"`
		} `json:"instances"`
	} `json:"resources"`
}

// ErrUnsupportedState is returned for files that are not Terraform state v4.
var ErrUnsupportedState = errors.New("not a Terraform state v4 file")

// Attributes never copied into the inventory: identifiers already used
// elsewhere, and the provider's merged tag copy.
var droppedStateAttrs = map[string]bool{"id": true, "arn": true, "tags": true, "tags_all": true, "region": true}

// FromTerraformState converts a Terraform state v4 document into an
// inventory snapshot. Only managed AWS resources are imported; data sources
// and other providers are skipped. Attributes Terraform marks sensitive are
// dropped, and the importer's own redaction still applies afterwards.
//
// Attribute names are the AWS provider's, which differ in places from the
// synthetic generator's (for example S3 public-access settings live on a
// separate aws_s3_bucket_public_access_block resource). Policies written
// against synthetic attributes may therefore report fewer findings for an
// imported state; see docs/modules/inventory.md.
func FromTerraformState(raw []byte, o StateOptions) (Snapshot, []string, error) {
	var st tfState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&st); err != nil {
		return Snapshot{}, nil, fmt.Errorf("%w: %v", ErrUnsupportedState, err)
	}
	if st.Version != 4 {
		return Snapshot{}, nil, fmt.Errorf("%w: version %d", ErrUnsupportedState, st.Version)
	}
	captured := o.CapturedAt
	if captured.IsZero() {
		captured = time.Now().UTC()
	}
	snap := Snapshot{SchemaVersion: SchemaV1, Source: "terraform_state", CapturedAt: captured,
		Account: Account{Provider: "aws", ExternalID: o.AccountID, Name: o.AccountName}}
	var skipped []string
	ids := map[string]bool{}
	type pending struct {
		idx  int
		deps []string
	}
	var deps []pending
	for _, r := range st.Resources {
		if r.Mode != "managed" || !strings.Contains(r.Provider, "hashicorp/aws") {
			skipped = append(skipped, address(r.Module, r.Type, r.Name, nil)+" (not a managed AWS resource)")
			continue
		}
		for _, in := range r.Instances {
			addr := address(r.Module, r.Type, r.Name, in.IndexKey)
			attrs := in.Attributes
			res := Resource{ResourceID: addr, ResourceType: r.Type, Environment: o.Environment,
				Tags: stringMap(attrs["tags"]), Configuration: map[string]any{}}
			if reg, ok := attrs["region"].(string); ok {
				res.Region = reg
			}
			if arn, ok := attrs["arn"].(string); ok {
				region, account := parseARN(arn)
				if res.Region == "" {
					res.Region = region
				}
				if snap.Account.ExternalID == "" && account != "" {
					snap.Account.ExternalID = account
				}
			}
			sensitive := sensitiveTopLevel(in.SensitiveAttributes)
			for k, v := range attrs {
				if droppedStateAttrs[k] || sensitive[k] || v == nil {
					continue
				}
				res.Configuration[k] = v
			}
			if len(res.Tags) == 0 {
				res.Tags = nil
			}
			ids[addr] = true
			deps = append(deps, pending{len(snap.Resources), in.Dependencies})
			snap.Resources = append(snap.Resources, res)
		}
	}
	// Dependencies name resources ("aws_kms_key.main"), which for counted or
	// for_each resources match no single instance; keep the edges that resolve.
	for _, p := range deps {
		seen := map[string]bool{}
		for _, d := range p.deps {
			if ids[d] && !seen[d] {
				seen[d] = true
				snap.Resources[p.idx].Relationships = append(snap.Resources[p.idx].Relationships, Relationship{Type: "depends_on", TargetID: d})
			}
		}
	}
	if snap.Account.Name == "" {
		snap.Account.Name = "terraform-" + snap.Account.ExternalID
	}
	sort.Slice(snap.Resources, func(i, j int) bool { return snap.Resources[i].ResourceID < snap.Resources[j].ResourceID })
	return snap, skipped, nil
}

func address(module, typ, name string, key any) string {
	a := typ + "." + name
	if module != "" {
		a = module + "." + a
	}
	switch k := key.(type) {
	case nil:
	case string:
		a += fmt.Sprintf("[%q]", k)
	default:
		a += fmt.Sprintf("[%v]", k)
	}
	return a
}

// parseARN returns the region and account of arn:partition:service:region:account:resource.
func parseARN(arn string) (region, account string) {
	p := strings.SplitN(arn, ":", 6)
	if len(p) < 6 || p[0] != "arn" {
		return "", ""
	}
	if awsAccountID.MatchString(p[4]) {
		account = p[4]
	}
	return p[3], account
}

func stringMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		}
	}
	return out
}

// sensitiveTopLevel returns the top-level attribute names Terraform marked
// sensitive, from the [[{"type":"get_attr","value":"x"}, ...], ...] path
// encoding. Anything unparseable marks nothing; the importer's redaction of
// sensitive-looking keys still runs afterwards.
func sensitiveTopLevel(raw json.RawMessage) map[string]bool {
	out := map[string]bool{}
	var paths [][]struct {
		Type  string `json:"type"`
		Value any    `json:"value"`
	}
	if json.Unmarshal(raw, &paths) != nil {
		return out
	}
	for _, p := range paths {
		if len(p) > 0 && p[0].Type == "get_attr" {
			if s, ok := p[0].Value.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}
