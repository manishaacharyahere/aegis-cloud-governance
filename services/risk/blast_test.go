package risk

import (
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
)

func syntheticGraph(n int) (*Graph, []Finding) {
	ds := synthetic.Generate(synthetic.Options{Seed: 42, Resources: n, CapturedAt: time.Now()})
	var nodes []Node
	var edges []Edge
	for _, r := range inventory.Normalize(ds.Snapshot).Resources {
		nodes = append(nodes, Node{ID: r.ResourceID, Type: r.ResourceType, Environment: r.Environment, Tags: r.Tags, Configuration: r.Configuration})
		for _, rel := range r.Relationships {
			edges = append(edges, Edge{r.ResourceID, rel.Type, rel.TargetID})
		}
	}
	var findings []Finding
	for id, issues := range ds.Labels {
		for _, issue := range issues {
			findings = append(findings, Finding{RuleID: issue, Subject: id, Severity: "high"})
		}
	}
	return BuildGraph(nodes, edges), findings
}

func BenchmarkAssess10k(b *testing.B) {
	g, findings := syntheticGraph(10000)
	b.ResetTimer()
	for range b.N {
		Assess(g, findings, DefaultWeights(), time.Now())
	}
}
