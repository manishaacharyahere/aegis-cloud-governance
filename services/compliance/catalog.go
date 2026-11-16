// Package compliance implements Module C (policy and compliance engine):
// a versioned control catalog, rule-to-control mappings, reproducible
// evaluations with evidence, expiring exceptions with separation of duties,
// and coverage reporting with evidence freshness.
package compliance

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

//go:embed catalog.json
var catalogJSON []byte

// Catalog is the control catalog: frameworks, Aegis rules and mappings.
type Catalog struct {
	Version    string      `json:"catalog_version"`
	Notice     string      `json:"notice"`
	Frameworks []Framework `json:"frameworks"`
	Rules      []Rule      `json:"rules"`
	Mappings   []Mapping   `json:"mappings"`

	SHA256    string                       `json:"-"`
	rules     map[string]Rule              `json:"-"`
	controls  map[string]map[string]string `json:"-"` // framework -> control -> title
	byControl map[string][]Mapping         `json:"-"` // framework/control -> mappings
}

type Framework struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Official  bool      `json:"official"`
	SourceURL string    `json:"source_url"`
	Controls  []Control `json:"controls"`
}

type Control struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type Rule struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	AppliesTo struct {
		Terraform []string `json:"terraform"`
		Inventory []string `json:"inventory"`
	} `json:"applies_to"`
	Remediation string `json:"remediation"`
	// ChangeRule rules judge the planned change itself (e.g. a deletion), so
	// they also apply to resources that will not exist after apply.
	ChangeRule bool `json:"change_rule,omitempty"`
}

type Mapping struct {
	Rule         string `json:"rule"`
	Framework    string `json:"framework"`
	Control      string `json:"control"`
	Coverage     string `json:"coverage"`      // full | partial
	ReviewStatus string `json:"review_status"` // reviewed | unreviewed
	Rationale    string `json:"rationale"`
}

var validSeverity = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}

// LoadCatalog parses and validates the embedded catalog.
func LoadCatalog() (*Catalog, error) { return ParseCatalog(catalogJSON) }

// ParseCatalog parses and validates catalog JSON, checking referential
// integrity so a broken mapping can never reach production.
func ParseCatalog(raw []byte) (*Catalog, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c Catalog
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	sum := sha256.Sum256(raw)
	c.SHA256 = hex.EncodeToString(sum[:])
	c.rules = map[string]Rule{}
	c.controls = map[string]map[string]string{}
	c.byControl = map[string][]Mapping{}

	var errs []error
	for _, f := range c.Frameworks {
		if _, dup := c.controls[f.ID]; dup {
			errs = append(errs, fmt.Errorf("duplicate framework %s", f.ID))
		}
		c.controls[f.ID] = map[string]string{}
		for _, ctl := range f.Controls {
			if _, dup := c.controls[f.ID][ctl.ID]; dup {
				errs = append(errs, fmt.Errorf("duplicate control %s/%s", f.ID, ctl.ID))
			}
			c.controls[f.ID][ctl.ID] = ctl.Title
		}
	}
	for _, r := range c.Rules {
		if _, dup := c.rules[r.ID]; dup {
			errs = append(errs, fmt.Errorf("duplicate rule %s", r.ID))
		}
		if !validSeverity[r.Severity] {
			errs = append(errs, fmt.Errorf("rule %s: invalid severity %q", r.ID, r.Severity))
		}
		if len(r.AppliesTo.Terraform)+len(r.AppliesTo.Inventory) == 0 {
			errs = append(errs, fmt.Errorf("rule %s applies to nothing", r.ID))
		}
		c.rules[r.ID] = r
	}
	seen := map[string]bool{}
	for _, m := range c.Mappings {
		key := m.Rule + "|" + m.Framework + "|" + m.Control
		if seen[key] {
			errs = append(errs, fmt.Errorf("duplicate mapping %s", key))
		}
		seen[key] = true
		if _, ok := c.rules[m.Rule]; !ok {
			errs = append(errs, fmt.Errorf("mapping references unknown rule %s", m.Rule))
		}
		if _, ok := c.controls[m.Framework][m.Control]; !ok {
			errs = append(errs, fmt.Errorf("mapping references unknown control %s/%s", m.Framework, m.Control))
		}
		if m.Coverage != "full" && m.Coverage != "partial" {
			errs = append(errs, fmt.Errorf("mapping %s: coverage must be full or partial", key))
		}
		if m.ReviewStatus != "reviewed" && m.ReviewStatus != "unreviewed" {
			errs = append(errs, fmt.Errorf("mapping %s: review_status must be reviewed or unreviewed", key))
		}
		if strings.TrimSpace(m.Rationale) == "" {
			errs = append(errs, fmt.Errorf("mapping %s: rationale required", key))
		}
		c.byControl[m.Framework+"/"+m.Control] = append(c.byControl[m.Framework+"/"+m.Control], m)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("invalid catalog: %w", err)
	}
	return &c, nil
}

// Rule returns rule metadata.
func (c *Catalog) Rule(id string) (Rule, bool) { r, ok := c.rules[id]; return r, ok }

// RuleIDs returns all rule IDs, sorted.
func (c *Catalog) RuleIDs() []string {
	ids := make([]string, 0, len(c.rules))
	for id := range c.rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Framework returns a framework by ID.
func (c *Catalog) Framework(id string) (Framework, bool) {
	for _, f := range c.Frameworks {
		if f.ID == id {
			return f, true
		}
	}
	return Framework{}, false
}

// MappingsFor returns the rules mapped to a control.
func (c *Catalog) MappingsFor(framework, control string) []Mapping {
	return c.byControl[framework+"/"+control]
}

// ControlTitle returns a control's title and whether it exists.
func (c *Catalog) ControlTitle(framework, control string) (string, bool) {
	t, ok := c.controls[framework][control]
	return t, ok
}
