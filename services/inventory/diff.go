package inventory

import (
	"encoding/json"
	"reflect"
	"sort"
)

// ChangeType classifies how a resource changed between observations.
type ChangeType string

const (
	ChangeCreated   ChangeType = "created"
	ChangeUpdated   ChangeType = "updated"
	ChangeDeleted   ChangeType = "deleted"
	ChangeUnchanged ChangeType = "unchanged"
)

// Change describes one resource-level difference.
type Change struct {
	ResourceID   string     `json:"resource_id"`
	ResourceType string     `json:"resource_type"`
	Type         ChangeType `json:"change_type"`
	ChangedPaths []string   `json:"changed_paths,omitempty"`
}

// Current is the last known state of a resource in the system of record.
type Current struct {
	Resource NormalizedResource
	Deleted  bool
}

// Diff compares the current state with the next snapshot. Results are sorted
// by resource ID; unchanged resources are included so callers can update
// last-seen markers.
func Diff(current map[string]Current, next []NormalizedResource) []Change {
	changes := make([]Change, 0, len(next))
	present := make(map[string]bool, len(next))

	for _, n := range next {
		present[n.ResourceID] = true
		cur, ok := current[n.ResourceID]
		switch {
		case !ok || cur.Deleted:
			changes = append(changes, Change{ResourceID: n.ResourceID, ResourceType: n.ResourceType, Type: ChangeCreated})
		case cur.Resource.ContentSHA256 != n.ContentSHA256:
			changes = append(changes, Change{
				ResourceID: n.ResourceID, ResourceType: n.ResourceType, Type: ChangeUpdated,
				ChangedPaths: ChangedPaths(cur.Resource, n),
			})
		default:
			changes = append(changes, Change{ResourceID: n.ResourceID, ResourceType: n.ResourceType, Type: ChangeUnchanged})
		}
	}
	for id, cur := range current {
		if !present[id] && !cur.Deleted {
			changes = append(changes, Change{ResourceID: id, ResourceType: cur.Resource.ResourceType, Type: ChangeDeleted})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].ResourceID < changes[j].ResourceID })
	return changes
}

// ChangedPaths lists the attributes that differ, at field level for scalar
// fields and key level for tags and configuration (e.g.
// "configuration.public_access_block", "tags.owner").
func ChangedPaths(a, b NormalizedResource) []string {
	var paths []string
	scalar := func(name, x, y string) {
		if x != y {
			paths = append(paths, name)
		}
	}
	scalar("resource_type", a.ResourceType, b.ResourceType)
	scalar("native_type", a.NativeType, b.NativeType)
	scalar("region", a.Region, b.Region)
	scalar("environment", a.Environment, b.Environment)
	scalar("owner", a.Owner, b.Owner)

	for _, k := range unionKeys(a.Tags, b.Tags) {
		av, aok := a.Tags[k]
		bv, bok := b.Tags[k]
		if aok != bok || av != bv {
			paths = append(paths, "tags."+k)
		}
	}
	for _, k := range unionKeys(a.Configuration, b.Configuration) {
		if !jsonEqual(a.Configuration[k], b.Configuration[k]) {
			paths = append(paths, "configuration."+k)
		}
	}
	if !reflect.DeepEqual(a.Relationships, b.Relationships) {
		paths = append(paths, "relationships")
	}
	return paths
}

func unionKeys[V any](a, b map[string]V) []string {
	set := make(map[string]bool, len(a)+len(b))
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// jsonEqual compares values by canonical JSON, so json.Number("1") read from
// the database and from a request compare equal.
func jsonEqual(a, b any) bool {
	x, err1 := json.Marshal(a)
	y, err2 := json.Marshal(b)
	return err1 == nil && err2 == nil && string(x) == string(y)
}
