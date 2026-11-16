package synthetic

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func gen1000(seed uint64) Dataset {
	return Generate(Options{Seed: seed, Resources: 1000, CapturedAt: t0})
}

func TestGenerateIsDeterministic(t *testing.T) {
	a, _ := json.Marshal(gen1000(42))
	b, _ := json.Marshal(gen1000(42))
	if string(a) != string(b) {
		t.Fatal("same seed produced different output")
	}
	c, _ := json.Marshal(gen1000(43))
	if string(a) == string(c) {
		t.Fatal("different seeds produced identical output")
	}
}

func TestGeneratedSnapshotIsValidAndLargeEnough(t *testing.T) {
	d := gen1000(42)
	if n := len(d.Snapshot.Resources); n < 1000 {
		t.Fatalf("got %d resources, want >= 1000", n)
	}
	if err := inventory.Validate(d.Snapshot, t0.Add(time.Hour)); err != nil {
		t.Fatalf("generated snapshot invalid: %v", err)
	}
	ns := inventory.Normalize(d.Snapshot)
	for _, w := range ns.Warnings {
		if w.Code == "unknown_resource_type" || w.Code == "dangling_relationship" || w.Code == "unknown_environment" {
			t.Fatalf("unexpected warning: %+v", w)
		}
	}
}

func TestLabelsMatchInjectedConfiguration(t *testing.T) {
	d := gen1000(7)
	byID := map[string]inventory.Resource{}
	for _, r := range d.Snapshot.Resources {
		byID[r.ResourceID] = r
	}
	counts := map[string]int{}
	for id, issues := range d.Labels {
		r, ok := byID[id]
		if !ok {
			t.Fatalf("label for unknown resource %s", id)
		}
		for _, is := range issues {
			counts[is]++
			switch is {
			case IssuePublicBucket:
				if r.Configuration["public_access_block"] != false {
					t.Errorf("%s labelled public but config %v", id, r.Configuration)
				}
			case IssueUnencryptedStorage:
				if _, has := r.Configuration["encryption"]; has {
					t.Errorf("%s labelled unencrypted but has encryption", id)
				}
			case IssueMissingTags:
				if r.Tags["owner"] != "" {
					t.Errorf("%s labelled missing tags but has owner", id)
				}
			}
		}
	}
	// Unlabelled buckets must be secure.
	for id, r := range byID {
		if r.ResourceType == "aws_s3_bucket" && !slices.Contains(d.Labels[id], IssuePublicBucket) &&
			r.Configuration["public_access_block"] != true {
			t.Errorf("unlabelled bucket %s is public", id)
		}
	}
	for _, issue := range []string{IssuePublicBucket, IssueUnencryptedStorage, IssueWildcardIAM, IssueOpenSSH, IssueMissingTags} {
		if counts[issue] == 0 {
			t.Errorf("no %s injected in 1000 resources", issue)
		}
	}
}

func TestMutateProducesExactGroundTruth(t *testing.T) {
	base := gen1000(42)
	baseJSON, _ := json.Marshal(base)
	next, m := Mutate(base, MutateOptions{Seed: 1, Modify: 25, Delete: 10, Add: 15, CapturedAt: t0.Add(24 * time.Hour)})

	if after, _ := json.Marshal(base); string(after) != string(baseJSON) {
		t.Fatal("Mutate modified its input")
	}
	if len(m.Modified) != 25 || len(m.Deleted) != 10 || len(m.Added) != 15 {
		t.Fatalf("mutation sizes: %d %d %d", len(m.Modified), len(m.Deleted), len(m.Added))
	}
	if err := inventory.Validate(next.Snapshot, t0.Add(48*time.Hour)); err != nil {
		t.Fatalf("mutated snapshot invalid: %v", err)
	}

	// The inventory diff engine must find exactly the injected changes.
	cur := map[string]inventory.Current{}
	for _, r := range inventory.Normalize(base.Snapshot).Resources {
		cur[r.ResourceID] = inventory.Current{Resource: r}
	}
	got := map[inventory.ChangeType][]string{}
	for _, c := range inventory.Diff(cur, inventory.Normalize(next.Snapshot).Resources) {
		got[c.Type] = append(got[c.Type], c.ResourceID)
	}
	slices.Sort(got[inventory.ChangeCreated])

	if !slices.Equal(got[inventory.ChangeDeleted], m.Deleted) {
		t.Errorf("deleted: got %v want %v", got[inventory.ChangeDeleted], m.Deleted)
	}
	if !slices.Equal(got[inventory.ChangeCreated], m.Added) {
		t.Errorf("created: got %v want %v", got[inventory.ChangeCreated], m.Added)
	}
	// Updated = modified resources plus resources whose relationships pointed at a deleted one.
	for _, id := range m.Modified {
		if !slices.Contains(got[inventory.ChangeUpdated], id) {
			t.Errorf("modified %s not detected as updated", id)
		}
	}
}
