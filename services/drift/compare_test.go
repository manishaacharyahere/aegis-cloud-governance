package drift

import (
	"encoding/json"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
)

func states(s inventory.Snapshot) map[string]State {
	out := map[string]State{}
	for _, n := range inventory.Normalize(s).Resources {
		out[n.ResourceID] = FromNormalized(n)
	}
	return out
}

func byCategory(items []Item) map[string][]string {
	out := map[string][]string{}
	for _, it := range items {
		out[it.Category] = append(out[it.Category], it.ResourceID)
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}

// The engine must find exactly the drift the generator injected.
func TestCompareMatchesSyntheticGroundTruth(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v1 := synthetic.Generate(synthetic.Options{Seed: 42, Resources: 1000, CapturedAt: t0})
	v2, m := synthetic.Mutate(v1, synthetic.MutateOptions{Seed: 7, Modify: 25, Delete: 10, Add: 15, CapturedAt: t0.Add(time.Hour)})

	items := Compare(DefaultConfig(), states(v1.Snapshot), states(v2.Snapshot), nil, nil, nil)
	cats := byCategory(items)
	if !slices.Equal(cats[CategoryDeleted], m.Deleted) {
		t.Errorf("deleted: got %v want %v", cats[CategoryDeleted], m.Deleted)
	}
	if !slices.Equal(cats[CategoryUnmanaged], m.Added) {
		t.Errorf("unmanaged: got %v want %v", cats[CategoryUnmanaged], m.Added)
	}
	var changed []string
	for _, c := range []string{CategorySecurity, CategoryCost, CategoryConfiguration, CategoryTagging} {
		changed = append(changed, cats[c]...)
	}
	sort.Strings(changed)
	if !slices.Equal(changed, m.Modified) {
		t.Errorf("modified: got %d %v\nwant %d %v", len(changed), changed, len(m.Modified), m.Modified)
	}

	// Category follows what the generator changed.
	byID := map[string]Item{}
	for _, it := range items {
		byID[it.ResourceID] = it
	}
	typ := map[string]string{}
	for _, r := range v1.Snapshot.Resources {
		typ[r.ResourceID] = r.ResourceType
	}
	for _, id := range m.Modified {
		want := CategoryTagging
		switch typ[id] {
		case "aws_s3_bucket":
			want = CategorySecurity
			if len(byID[id].Changes) == 1 && byID[id].Changes[0].Path == "configuration.versioning" {
				want = CategoryConfiguration // already public and unencrypted: versioning flipped
			}
		case "aws_security_group":
			want = CategorySecurity
		case "aws_instance":
			want = CategoryCost
		}
		if got := byID[id].Category; got != want {
			t.Errorf("%s (%s): category %s, want %s (changes %+v)", id, typ[id], got, want, byID[id].Changes)
		}
	}
}

func TestCanonicalisationAvoidsFalseDrift(t *testing.T) {
	cfg := DefaultConfig()
	a := State{ResourceID: "sg", Type: "network.security_group", Tags: map[string]string{"owner": "x", "last_scanned": "mon"},
		Configuration: map[string]any{
			"ingress": []any{
				map[string]any{"protocol": "tcp", "from_port": 443, "to_port": 443},
				map[string]any{"from_port": 80, "protocol": "tcp", "to_port": 80},
			},
			"nested":        map[string]any{"b": 1, "a": json.Number("2.0")},
			"last_modified": "2026-01-01",
		}}
	b := State{ResourceID: "sg", Type: "network.security_group", Tags: map[string]string{"owner": "x", "last_scanned": "tue"},
		Configuration: map[string]any{
			"ingress": []any{ // reordered, numbers as float64
				map[string]any{"to_port": float64(80), "protocol": "tcp", "from_port": float64(80)},
				map[string]any{"protocol": "tcp", "to_port": json.Number("443"), "from_port": 443},
			},
			"nested":        map[string]any{"a": 2, "b": float64(1)},
			"last_modified": "2026-11-16", // volatile
		}}
	if items := Compare(cfg, map[string]State{"sg": a}, map[string]State{"sg": b}, nil, nil, nil); len(items) != 0 {
		t.Fatalf("false drift: %+v", items)
	}

	// Provider defaults: an absent attribute equals its default.
	bucketA := State{ResourceID: "b", Type: "storage.bucket", Configuration: map[string]any{"encryption": "aws:kms"}}
	bucketB := State{ResourceID: "b", Type: "storage.bucket", Configuration: map[string]any{"encryption": "aws:kms", "versioning": false}}
	if items := Compare(cfg, map[string]State{"b": bucketA}, map[string]State{"b": bucketB}, nil, nil, nil); len(items) != 0 {
		t.Fatalf("default value treated as drift: %+v", items)
	}

	// But a real change to an ordered list or a value is drift.
	bucketB.Configuration["versioning"] = true
	if items := Compare(cfg, map[string]State{"b": bucketA}, map[string]State{"b": bucketB}, nil, nil, nil); len(items) != 1 {
		t.Fatalf("real change missed: %+v", items)
	}
}

func TestPolicyDeltaRaisesSeverity(t *testing.T) {
	cfg := DefaultConfig()
	a := State{ResourceID: "b", Type: "storage.bucket", Configuration: map[string]any{"public_access_block": true}}
	o := State{ResourceID: "b", Type: "storage.bucket", Configuration: map[string]any{"public_access_block": false}}
	sev := map[string]string{"AEGIS-S3-001": "high", "AEGIS-DB-002": "critical"}
	items := Compare(cfg, map[string]State{"b": a}, map[string]State{"b": o},
		map[string][]string{}, map[string][]string{"b": {"AEGIS-S3-001"}}, sev)
	if len(items) != 1 || items[0].Category != CategorySecurity || items[0].Severity != "high" ||
		!slices.Equal(items[0].NewFailures, []string{"AEGIS-S3-001"}) {
		t.Fatalf("policy delta: %+v", items)
	}

	// Fixing a violation is still drift (from the approved state) but records what was resolved.
	items = Compare(cfg, map[string]State{"b": o}, map[string]State{"b": a},
		map[string][]string{"b": {"AEGIS-S3-001"}}, map[string][]string{}, sev)
	if len(items) != 1 || !slices.Equal(items[0].Resolved, []string{"AEGIS-S3-001"}) || items[0].Severity != "medium" {
		t.Fatalf("resolved: %+v", items)
	}

	// Unmanaged resources take the severity of the worst rule failing on them.
	items = Compare(cfg, nil, map[string]State{"db": {ResourceID: "db", Type: "database.instance"}},
		nil, map[string][]string{"db": {"AEGIS-DB-002"}}, sev)
	if items[0].Category != CategoryUnmanaged || items[0].Severity != "critical" {
		t.Fatalf("unmanaged: %+v", items)
	}
}

func TestDeletedStatefulIsHigh(t *testing.T) {
	items := Compare(DefaultConfig(),
		map[string]State{"db": {ResourceID: "db", Type: "database.instance"}, "sg": {ResourceID: "sg", Type: "network.security_group"}},
		map[string]State{}, nil, nil, nil)
	got := map[string]string{}
	for _, it := range items {
		got[it.ResourceID] = it.Severity
	}
	if got["db"] != "high" || got["sg"] != "medium" || items[0].ResourceID != "db" {
		t.Fatalf("deleted severities / ordering: %+v", items)
	}
}

func TestIgnorePatterns(t *testing.T) {
	c := Config{Ignore: []string{"tags.aegis_*", "configuration.metadata.*", "region"}}
	for path, want := range map[string]bool{
		"tags.aegis_scan": true, "tags.owner": false, "configuration.metadata.etag": true,
		"configuration.metadata_version": false, "region": true, "regions": false,
	} {
		if got := c.ignored(path); got != want {
			t.Errorf("%s: ignored=%v want %v", path, got, want)
		}
	}
	if DefaultConfig().SHA256() == (Config{}).SHA256() {
		t.Error("config hash must reflect content")
	}
}

// Across many seeds, every generator "modification" must be detected and
// nothing else may drift.
func TestCompareGroundTruthAcrossSeeds(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for seed := uint64(1); seed <= 200; seed++ {
		v1 := synthetic.Generate(synthetic.Options{Seed: seed, Resources: 300, CapturedAt: t0})
		v2, m := synthetic.Mutate(v1, synthetic.MutateOptions{Seed: seed * 31, Modify: 40, Delete: 5, Add: 5, CapturedAt: t0.Add(time.Hour)})
		var changed []string
		for _, it := range Compare(DefaultConfig(), states(v1.Snapshot), states(v2.Snapshot), nil, nil, nil) {
			if it.Category != CategoryDeleted && it.Category != CategoryUnmanaged {
				changed = append(changed, it.ResourceID)
			}
		}
		sort.Strings(changed)
		if !slices.Equal(changed, m.Modified) {
			t.Fatalf("seed %d: detected %d modified, generator reports %d", seed, len(changed), len(m.Modified))
		}
	}
}
