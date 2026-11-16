package risk

import (
	"fmt"
	"sort"
	"time"
)

// Finding is a failing compliance evaluation to be prioritised.
type Finding struct {
	RuleID    string
	Severity  string
	Subject   string // resource ID
	FirstSeen time.Time
	Controls  int // number of mapped compliance controls (informational)
}

// Assessment is the explained risk of one finding.
type Assessment struct {
	RuleID        string             `json:"rule_id"`
	Subject       string             `json:"subject"`
	ResourceType  string             `json:"resource_type"`
	RuleSeverity  string             `json:"rule_severity"`
	Score         float64            `json:"score"`
	Band          string             `json:"band"`
	Factors       Factors            `json:"factors"`
	Contributions map[string]float64 `json:"contributions"`
	Reasons       []string           `json:"reasons"`
	BlastRadius   []string           `json:"blast_radius"`
	AttackPath    []Hop              `json:"attack_path,omitempty"`
	FirstSeen     *time.Time         `json:"first_seen,omitempty"`
	Controls      int                `json:"controls_affected"`
}

// Assess scores every finding against the graph. Pure and deterministic.
func Assess(g *Graph, findings []Finding, w Weights, now time.Time) []Assessment {
	reach := g.InternetReach()
	blast := map[string][]string{}
	maxSens := map[string]int{}
	out := make([]Assessment, 0, len(findings))
	for _, f := range findings {
		n := g.Nodes[f.Subject]
		if _, ok := blast[f.Subject]; !ok {
			blast[f.Subject], maxSens[f.Subject] = g.BlastRadius(f.Subject)
		}
		fac := Factors{
			Severity:    SeverityFactor(f.Severity),
			Privilege:   float64(g.Privilege(f.Subject)),
			Criticality: CriticalityFactor(n),
			Data:        float64(maxSens[f.Subject]),
			Age:         AgeFactor(f.FirstSeen, now),
		}
		a := Assessment{RuleID: f.RuleID, Subject: f.Subject, ResourceType: n.Type, RuleSeverity: f.Severity,
			BlastRadius: blast[f.Subject], Controls: f.Controls}
		if a.BlastRadius == nil {
			a.BlastRadius = []string{}
		}
		a.Reasons = append(a.Reasons, fmt.Sprintf("rule severity %s", f.Severity))
		if why := g.Exposed(f.Subject); why != "" {
			fac.Exposure = 100
			a.Reasons = append(a.Reasons, "directly internet-exposed: "+why)
			a.AttackPath = unwind(reach, Internet, f.Subject)
		} else if hops := unwind(reach, Internet, f.Subject); hops != nil {
			fac.Exposure = 70
			a.AttackPath = hops
			a.Reasons = append(a.Reasons, fmt.Sprintf("reachable from the internet in %d hops", len(hops)))
		}
		switch {
		case fac.Privilege >= 100:
			a.Reasons = append(a.Reasons, "grants full administrative privileges")
		case fac.Privilege >= 80:
			a.Reasons = append(a.Reasons, "can assume a role with full administrative privileges")
		}
		if len(a.BlastRadius) > 0 {
			a.Reasons = append(a.Reasons, fmt.Sprintf("can reach %d sensitive data store(s)", len(a.BlastRadius)))
		} else if s := Sensitivity(n); s > 0 {
			a.Reasons = append(a.Reasons, fmt.Sprintf("holds data with sensitivity %d", s))
		}
		if n.Environment != "" {
			a.Reasons = append(a.Reasons, "environment "+n.Environment)
		}
		if !f.FirstSeen.IsZero() {
			fs := f.FirstSeen
			a.FirstSeen = &fs
			if days := int(now.Sub(fs).Hours() / 24); days >= 1 {
				a.Reasons = append(a.Reasons, fmt.Sprintf("unresolved for %d day(s)", days))
			}
		}
		a.Factors = fac
		a.Score = Score(fac, w)
		a.Band = Band(a.Score)
		a.Contributions = Contributions(fac, w)
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

// Comparison contrasts static severity ordering with contextual risk. It
// avoids top-K overlap with a severity-sorted list: many findings share a
// severity, so such a list depends on arbitrary tie-breaking.
type Comparison struct {
	Findings                int            `json:"findings"`
	TopK                    int            `json:"top_k"`
	TopKSeverityMix         map[string]int `json:"top_k_severity_mix"`         // rule severities among the risk top-K
	CriticalSeverityLowRisk int            `json:"critical_severity_low_risk"` // critical rule, band low/medium
	LowSeverityHighRisk     int            `json:"low_severity_high_risk"`     // medium/low rule, band high/critical
}

// CompareWithSeverity measures how contextual scoring re-orders findings
// relative to rule severity alone. as must be sorted by score.
func CompareWithSeverity(as []Assessment, k int) Comparison {
	c := Comparison{Findings: len(as), TopK: min(k, len(as)), TopKSeverityMix: map[string]int{}}
	for _, a := range as[:c.TopK] {
		c.TopKSeverityMix[a.RuleSeverity]++
	}
	for _, a := range as {
		if a.RuleSeverity == "critical" && (a.Band == "low" || a.Band == "medium") {
			c.CriticalSeverityLowRisk++
		}
		if (a.RuleSeverity == "medium" || a.RuleSeverity == "low") && (a.Band == "high" || a.Band == "critical") {
			c.LowSeverityHighRisk++
		}
	}
	return c
}
