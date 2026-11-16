package risk

import (
	"math"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
)

var now = time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)

// A small hand-built environment with one complete attack chain:
// internet -> public LB -> web instance -> admin role -> customer DB.
func testGraph() *Graph {
	prod := map[string]string{"environment": "production"}
	nodes := []Node{
		{ID: "lb", Type: "network.load_balancer", Environment: "production", Configuration: map[string]any{"internal": false}},
		{ID: "web", Type: "compute.instance", Environment: "production", Tags: prod, Configuration: map[string]any{}},
		{ID: "batch", Type: "compute.instance", Environment: "production", Configuration: map[string]any{}},
		{ID: "admin-role", Type: "identity.role", Configuration: map[string]any{}},
		{ID: "admin-policy", Type: "identity.policy", Configuration: map[string]any{"statements": []any{
			map[string]any{"effect": "Allow", "actions": []any{"*"}, "resources": []any{"*"}}}}},
		{ID: "customer-db", Type: "database.instance", Environment: "production", Configuration: map[string]any{"publicly_accessible": false}},
		{ID: "dev-bucket", Type: "storage.bucket", Environment: "development", Configuration: map[string]any{"public_access_block": true}},
		{ID: "public-site", Type: "storage.bucket", Environment: "production",
			Tags: map[string]string{"data_classification": "public"}, Configuration: map[string]any{"public_access_block": false}},
		{ID: "ssh-sg", Type: "network.security_group", Configuration: map[string]any{"ingress": []any{
			map[string]any{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": []any{"0.0.0.0/0"}}}}},
		{ID: "vpc", Type: "network.vpc"},
	}
	edges := []Edge{
		{"lb", "routes_to", "web"},
		{"web", "assumes", "admin-role"},
		{"admin-policy", "attached_to", "admin-role"},
		{"batch", "writes_to", "dev-bucket"},
		{"ssh-sg", "attached_to", "batch"},
		{"web", "member_of", "vpc"}, // structural: must not create movement
	}
	return BuildGraph(nodes, edges)
}

func TestAttackPathThroughAdminRole(t *testing.T) {
	g := testGraph()
	paths := g.AttackPaths(50, 0)
	if len(paths) == 0 || paths[0].Target != "customer-db" {
		t.Fatalf("expected customer-db path first, got %+v", paths)
	}
	var vias []string
	for _, h := range paths[0].Hops {
		vias = append(vias, h.From+">"+h.To)
	}
	want := []string{"internet>lb", "lb>web", "web>admin-role", "admin-role>customer-db"}
	if len(vias) != len(want) {
		t.Fatalf("path %v, want %v", vias, want)
	}
	for i := range want {
		if vias[i] != want[i] {
			t.Fatalf("path %v, want %v", vias, want)
		}
	}
	for _, p := range paths {
		if p.Target == "public-site" {
			t.Error("data classified public is not a sensitive target")
		}
		for _, h := range p.Hops {
			if h.To == "vpc" {
				t.Error("structural member_of edge used as a movement path")
			}
		}
	}
}

func TestExposurePrivilegeAndBlastRadius(t *testing.T) {
	g := testGraph()
	if g.Exposed("lb") == "" || g.Exposed("batch") == "" || g.Exposed("public-site") == "" {
		t.Error("expected lb, batch (open SG) and public bucket to be exposed")
	}
	if g.Exposed("web") != "" || g.Exposed("customer-db") != "" {
		t.Error("web and the private DB are not directly exposed")
	}
	if g.Privilege("admin-policy") != PrivAdmin || g.Privilege("admin-role") != PrivAdmin || g.Privilege("web") != 80 {
		t.Errorf("privilege: policy=%d role=%d web=%d", g.Privilege("admin-policy"), g.Privilege("admin-role"), g.Privilege("web"))
	}
	stores, sens := g.BlastRadius("web")
	if len(stores) != 2 || sens != 90 { // customer-db (90) and dev-bucket (50) via the admin role
		t.Errorf("blast radius of web: %v sensitivity %d", stores, sens)
	}
}

func TestContextChangesPriority(t *testing.T) {
	g := testGraph()
	findings := []Finding{
		{RuleID: "AEGIS-TAG-001", Severity: "medium", Subject: "web", FirstSeen: now.Add(-40 * 24 * time.Hour)},
		{RuleID: "AEGIS-S3-002", Severity: "medium", Subject: "dev-bucket"},
	}
	as := Assess(g, findings, DefaultWeights(), now)
	if as[0].Subject != "web" || as[0].Factors.Exposure != 70 || as[0].Factors.Age != 100 || len(as[0].AttackPath) != 2 {
		t.Fatalf("web should rank first with path exposure: %+v", as[0])
	}
	// The dev bucket is not public, but batch (behind an internet-open SSH
	// security group) writes to it: reachable in two hops, scored medium.
	if as[1].Subject != "dev-bucket" || as[1].Factors.Exposure != 70 || len(as[1].AttackPath) != 2 ||
		as[1].AttackPath[0].To != "batch" || as[1].Band != "medium" {
		t.Errorf("dev bucket via batch: %+v", as[1])
	}
	sum := 0.0
	for _, v := range as[0].Contributions {
		sum += v
	}
	if math.Abs(sum-as[0].Score) > 0.35 {
		t.Errorf("contributions %.1f do not explain score %.1f", sum, as[0].Score)
	}
	if len(as[0].Reasons) < 4 {
		t.Errorf("explanation too thin: %v", as[0].Reasons)
	}
}

func TestScoreProperties(t *testing.T) {
	w := DefaultWeights()
	if err := w.Validate(); err != nil {
		t.Fatal(err)
	}
	if Score(Factors{100, 100, 100, 100, 100, 100}, w) != 100 || Score(Factors{}, w) != 0 {
		t.Error("bounds")
	}
	// Monotonic: raising any factor never lowers the score.
	base := Factors{50, 50, 50, 50, 50, 50}
	b := Score(base, w)
	for i := range FactorNames {
		f := base.slice()
		f[i] = 90
		up := Factors{f[0], f[1], f[2], f[3], f[4], f[5]}
		if Score(up, w) < b {
			t.Errorf("raising %s lowered the score", FactorNames[i])
		}
	}
	if Score(Factors{Severity: 500}, w) != 30 {
		t.Error("factors must be clamped to 100")
	}
	for _, bad := range []Weights{{Severity: 1, Exposure: 0.5}, {Severity: -0.1, Exposure: 1.1}, {Severity: math.NaN()}} {
		if bad.Validate() == nil {
			t.Errorf("invalid weights accepted: %+v", bad)
		}
	}
	for score, band := range map[float64]string{80: "critical", 79.9: "high", 60: "high", 40: "medium", 39.9: "low"} {
		if Band(score) != band {
			t.Errorf("Band(%v) = %s", score, Band(score))
		}
	}
	if AgeFactor(now.Add(-15*24*time.Hour), now) != 50 || AgeFactor(time.Time{}, now) != 0 || AgeFactor(now.Add(time.Hour), now) != 0 {
		t.Error("age factor")
	}
}

func TestSensitivityAnalysis(t *testing.T) {
	items := []Ranked{
		{"a", Factors{100, 100, 0, 100, 90, 0}},
		{"b", Factors{75, 0, 0, 100, 50, 100}},
		{"c", Factors{50, 70, 80, 50, 90, 10}},
		{"d", Factors{25, 0, 0, 20, 0, 0}},
	}
	res, err := SensitivityAnalysis(items, DefaultWeights(), 0.2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 12 {
		t.Fatalf("want 6 factors x 2 directions, got %d", len(res))
	}
	for _, r := range res {
		if r.Spearman < -1 || r.Spearman > 1 || r.TopKOverlap < 0 || r.TopKOverlap > 1 {
			t.Errorf("out of range: %+v", r)
		}
	}
	if _, err := SensitivityAnalysis(items[:1], DefaultWeights(), 0.2, 1); err != ErrTooFew {
		t.Error("expected ErrTooFew")
	}
}

// On the synthetic estate, every internet-reachable sensitive target must have
// a valid path where each hop starts where the previous one ended.
func TestSyntheticEstatePathsAreWellFormed(t *testing.T) {
	ds := synthetic.Generate(synthetic.Options{Seed: 42, Resources: 1000, CapturedAt: now})
	var nodes []Node
	var edges []Edge
	for _, r := range inventory.Normalize(ds.Snapshot).Resources {
		nodes = append(nodes, Node{ID: r.ResourceID, Type: r.ResourceType, Environment: r.Environment, Tags: r.Tags, Configuration: r.Configuration})
		for _, rel := range r.Relationships {
			edges = append(edges, Edge{r.ResourceID, rel.Type, rel.TargetID})
		}
	}
	g := BuildGraph(nodes, edges)
	paths := g.AttackPaths(50, 0)
	if len(paths) == 0 {
		t.Fatal("synthetic estate has public LBs, open SGs and admin roles; expected attack paths")
	}
	for _, p := range paths {
		if p.Hops[0].From != Internet || p.Hops[len(p.Hops)-1].To != p.Target || len(p.Hops) > MaxDepth {
			t.Fatalf("malformed path: %+v", p)
		}
		for i := 1; i < len(p.Hops); i++ {
			if p.Hops[i].From != p.Hops[i-1].To {
				t.Fatalf("broken path: %+v", p)
			}
		}
	}
	// Deterministic.
	again := BuildGraph(nodes, edges).AttackPaths(50, 0)
	if len(again) != len(paths) || again[0].Target != paths[0].Target {
		t.Error("attack paths are not deterministic")
	}
	t.Logf("synthetic estate: %d sensitive targets reachable from the internet", len(paths))
}

func TestCompareWithSeverity(t *testing.T) {
	as := []Assessment{
		{RuleSeverity: "medium", Band: "high"},
		{RuleSeverity: "critical", Band: "high"},
		{RuleSeverity: "critical", Band: "medium"},
		{RuleSeverity: "low", Band: "low"},
	}
	c := CompareWithSeverity(as, 2)
	if c.TopK != 2 || c.TopKSeverityMix["medium"] != 1 || c.TopKSeverityMix["critical"] != 1 ||
		c.CriticalSeverityLowRisk != 1 || c.LowSeverityHighRisk != 1 {
		t.Fatalf("comparison: %+v", c)
	}
	if CompareWithSeverity(as, 99).TopK != 4 {
		t.Error("top-k must be capped at the number of findings")
	}
}
