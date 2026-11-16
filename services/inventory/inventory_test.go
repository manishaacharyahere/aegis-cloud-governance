package inventory

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func validSnapshot() Snapshot {
	return Snapshot{
		SchemaVersion: SchemaV1,
		Source:        "synthetic",
		CapturedAt:    now.Add(-time.Hour),
		Account:       Account{Provider: "aws", ExternalID: "123456789012", Name: "demo-prod"},
		Resources: []Resource{
			{
				ResourceID:   "aws_s3_bucket.customer_data",
				ResourceType: "aws_s3_bucket",
				Region:       "ap-south-1",
				Tags:         map[string]string{"Environment": "prod", "owner": "payments-team", "cost_center": "payments"},
				Configuration: map[string]any{
					"public_access_block": false,
					"encryption":          "AES256",
					"versioning":          false,
				},
				Relationships: []Relationship{{Type: "encrypts", TargetID: "aws_kms_key.data"}},
			},
			{
				ResourceID:   "aws_kms_key.data",
				ResourceType: "security.kms_key",
				Region:       "ap-south-1",
				Environment:  "production",
				Owner:        "platform",
				Tags:         map[string]string{"owner": "platform", "environment": "production", "cost_center": "shared"},
			},
		},
	}
}

func issuesOf(t *testing.T, err error) []Issue {
	t.Helper()
	var v *ValidationError
	if !errors.As(err, &v) {
		t.Fatalf("want *ValidationError, got %v", err)
	}
	return v.Issues
}

func hasIssue(issues []Issue, path, substr string) bool {
	for _, i := range issues {
		if i.Path == path && strings.Contains(i.Message, substr) {
			return true
		}
	}
	return false
}

func TestValidateAcceptsValidSnapshot(t *testing.T) {
	if err := Validate(validSnapshot(), now); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRejections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		path   string
		substr string
	}{
		{"schema", func(s *Snapshot) { s.SchemaVersion = "v0" }, "schema_version", "must be"},
		{"source", func(s *Snapshot) { s.Source = "ftp" }, "source", "unsupported"},
		{"no time", func(s *Snapshot) { s.CapturedAt = time.Time{} }, "captured_at", "required"},
		{"future", func(s *Snapshot) { s.CapturedAt = now.Add(time.Hour) }, "captured_at", "future"},
		{"provider", func(s *Snapshot) { s.Account.Provider = "gcp" }, "account.provider", "unsupported"},
		{"account id", func(s *Snapshot) { s.Account.ExternalID = "12ab" }, "account.external_id", "12-digit"},
		{"account name", func(s *Snapshot) { s.Account.Name = " " }, "account.name", "characters"},
		{"empty id", func(s *Snapshot) { s.Resources[0].ResourceID = "" }, "resources[0].resource_id", "required"},
		{"id with space", func(s *Snapshot) { s.Resources[0].ResourceID = "a b" }, "resources[0].resource_id", "printable"},
		{"id control char", func(s *Snapshot) { s.Resources[0].ResourceID = "a\nb" }, "resources[0].resource_id", "printable"},
		{"duplicate id", func(s *Snapshot) { s.Resources[1].ResourceID = s.Resources[0].ResourceID }, "resources[1].resource_id", "duplicate"},
		{"no type", func(s *Snapshot) { s.Resources[0].ResourceType = "" }, "resources[0].resource_type", "required"},
		{"region", func(s *Snapshot) { s.Resources[0].Region = "mars-1" }, "resources[0].region", "invalid"},
		{"relationship type", func(s *Snapshot) { s.Resources[0].Relationships[0].Type = "likes" }, "resources[0].relationships[0].type", "unknown"},
		{"self relationship", func(s *Snapshot) { s.Resources[0].Relationships[0].TargetID = s.Resources[0].ResourceID }, "resources[0].relationships[0].target_id", "self"},
		{"deep config", func(s *Snapshot) {
			var v any = "leaf"
			for range MaxConfigDepth + 2 {
				v = map[string]any{"n": v}
			}
			s.Resources[0].Configuration = v.(map[string]any)
		}, "resources[0].configuration", "deeper"},
		{"long tag value", func(s *Snapshot) { s.Resources[0].Tags["owner"] = strings.Repeat("x", MaxTagValueLen+1) }, "resources[0].tags.owner", "longer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validSnapshot()
			tt.mutate(&s)
			issues := issuesOf(t, Validate(s, now))
			if !hasIssue(issues, tt.path, tt.substr) {
				t.Fatalf("missing issue %s ~ %q in %+v", tt.path, tt.substr, issues)
			}
		})
	}
}

func TestValidateRejectsTooManyResourcesWithoutIterating(t *testing.T) {
	s := validSnapshot()
	s.Resources = make([]Resource, MaxResources+1)
	issues := issuesOf(t, Validate(s, now))
	if len(issues) != 1 || issues[0].Path != "resources" {
		t.Fatalf("want single resources issue, got %d: %+v", len(issues), issues[:min(3, len(issues))])
	}
}

func TestValidateCapsIssueCount(t *testing.T) {
	s := validSnapshot()
	s.Resources = make([]Resource, 500) // every one invalid
	var v *ValidationError
	if !errors.As(Validate(s, now), &v) || len(v.Issues) != maxReportedIssues || !v.Truncated {
		t.Fatalf("issues not capped: %d truncated=%v", len(v.Issues), v.Truncated)
	}
}

func TestNormalizeMapsTypesEnvironmentAndOwner(t *testing.T) {
	n := Normalize(validSnapshot())
	if n.Resources[0].ResourceID != "aws_kms_key.data" {
		t.Fatalf("resources not sorted: %s", n.Resources[0].ResourceID)
	}
	b := n.Resources[1]
	if b.ResourceType != "storage.bucket" || b.NativeType != "aws_s3_bucket" {
		t.Errorf("type mapping: %s / %s", b.ResourceType, b.NativeType)
	}
	if b.Environment != "production" {
		t.Errorf("environment alias from tag: %q", b.Environment)
	}
	if b.Owner != "payments-team" {
		t.Errorf("owner from tag: %q", b.Owner)
	}
	if _, ok := b.Tags["environment"]; !ok {
		t.Error("tag keys should be lower-cased")
	}
	if n.Resources[0].ResourceType != "security.kms_key" {
		t.Errorf("already-normalised type changed: %s", n.Resources[0].ResourceType)
	}
}

func TestNormalizeWarnings(t *testing.T) {
	s := validSnapshot()
	s.Resources[0].Tags = map[string]string{}
	s.Resources[0].ResourceType = "aws_quantum_computer"
	s.Resources[0].Relationships = []Relationship{{Type: "depends_on", TargetID: "aws_vpc.missing"}}
	n := Normalize(s)

	codes := map[string]int{}
	for _, w := range n.Warnings {
		codes[w.Code]++
	}
	if codes["missing_tag"] != 3 || codes["unknown_resource_type"] != 1 || codes["dangling_relationship"] != 1 {
		t.Fatalf("unexpected warnings: %v", codes)
	}
	for _, r := range n.Resources {
		if r.ResourceID == "aws_s3_bucket.customer_data" && r.ResourceType != "other.aws_quantum_computer" {
			t.Errorf("unknown type not namespaced: %s", r.ResourceType)
		}
	}
}

func TestNormalizeRedactsSecretsRecursively(t *testing.T) {
	s := validSnapshot()
	s.Resources[0].Configuration = map[string]any{
		"master_password": "hunter2",
		"nested":          map[string]any{"API_KEY": "abc", "ok": 1},
		"list":            []any{map[string]any{"client_secret": "s"}},
		"token":           nil,
	}
	n := Normalize(s)
	var bucket NormalizedResource
	for _, r := range n.Resources {
		if r.ResourceID == "aws_s3_bucket.customer_data" {
			bucket = r
		}
	}
	raw, _ := json.Marshal(bucket.Configuration)
	for _, secret := range []string{"hunter2", `"abc"`, `"s"`} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("secret %s survived redaction: %s", secret, raw)
		}
	}
	var redacted []string
	for _, w := range n.Warnings {
		if w.Code == "sensitive_attribute_redacted" {
			redacted = append(redacted, w.Detail)
		}
	}
	slices.Sort(redacted)
	if want := []string{"list.client_secret", "master_password", "nested.API_KEY"}; !slices.Equal(redacted, want) {
		t.Errorf("redacted paths = %v, want %v", redacted, want)
	}
	// Input must not be mutated.
	if s.Resources[0].Configuration["master_password"] != "hunter2" {
		t.Error("Normalize mutated its input")
	}
}

func TestSnapshotHashIgnoresOrderingButNotContent(t *testing.T) {
	a := validSnapshot()
	b := validSnapshot()
	b.Resources[0], b.Resources[1] = b.Resources[1], b.Resources[0]
	b.Resources[1].Relationships = append(b.Resources[1].Relationships, b.Resources[1].Relationships...) // duplicate edge

	na, nb := Normalize(a), Normalize(b)
	if na.SHA256 != nb.SHA256 {
		t.Fatal("reordering resources or duplicating an edge changed the snapshot hash")
	}

	c := validSnapshot()
	c.Resources[0].Configuration["versioning"] = true
	if Normalize(c).SHA256 == na.SHA256 {
		t.Fatal("content change did not change the snapshot hash")
	}

	d := validSnapshot()
	d.CapturedAt = d.CapturedAt.Add(time.Minute)
	if Normalize(d).SHA256 == na.SHA256 {
		t.Fatal("a new capture time must be a new snapshot")
	}
}

func TestDiff(t *testing.T) {
	base := Normalize(validSnapshot()).Resources
	current := map[string]Current{}
	for _, r := range base {
		current[r.ResourceID] = Current{Resource: r}
	}
	current["aws_vpc.gone"] = Current{Resource: NormalizedResource{ResourceID: "aws_vpc.gone", ResourceType: "network.vpc"}}
	current["aws_vpc.already_deleted"] = Current{Resource: NormalizedResource{ResourceID: "aws_vpc.already_deleted"}, Deleted: true}

	s := validSnapshot()
	s.Resources[0].Configuration["public_access_block"] = true
	s.Resources[0].Tags["owner"] = "data-team"
	s.Resources = append(s.Resources, Resource{ResourceID: "aws_vpc.already_deleted", ResourceType: "aws_vpc"})
	next := Normalize(s).Resources

	got := map[string]Change{}
	for _, c := range Diff(current, next) {
		got[c.ResourceID] = c
	}
	if c := got["aws_s3_bucket.customer_data"]; c.Type != ChangeUpdated ||
		!slices.Equal(c.ChangedPaths, []string{"owner", "tags.owner", "configuration.public_access_block"}) {
		t.Errorf("bucket change = %+v", c)
	}
	if got["aws_kms_key.data"].Type != ChangeUnchanged {
		t.Errorf("kms should be unchanged: %+v", got["aws_kms_key.data"])
	}
	if got["aws_vpc.gone"].Type != ChangeDeleted {
		t.Errorf("vpc should be deleted: %+v", got["aws_vpc.gone"])
	}
	if got["aws_vpc.already_deleted"].Type != ChangeCreated {
		t.Errorf("reappearing resource should be created: %+v", got["aws_vpc.already_deleted"])
	}
	if len(got) != 4 {
		t.Errorf("unexpected change count %d: %+v", len(got), got)
	}
}

func TestDiffEmptyCurrentCreatesEverything(t *testing.T) {
	for _, c := range Diff(nil, Normalize(validSnapshot()).Resources) {
		if c.Type != ChangeCreated {
			t.Fatalf("want created, got %+v", c)
		}
	}
}

func TestChangedPathsTreatsNumbersCanonically(t *testing.T) {
	a := NormalizedResource{Configuration: map[string]any{"port": json.Number("22")}}
	b := NormalizedResource{Configuration: map[string]any{"port": float64(22)}}
	if p := ChangedPaths(a, b); len(p) != 0 {
		t.Fatalf("json.Number vs float64 reported as change: %v", p)
	}
}
