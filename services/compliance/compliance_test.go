package compliance

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func cat(t *testing.T) *Catalog {
	t.Helper()
	c, err := LoadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEmbeddedCatalogIsValid(t *testing.T) {
	c := cat(t)
	if len(c.SHA256) != 64 || len(c.Frameworks) != 3 || len(c.RuleIDs()) != 12 {
		t.Fatalf("catalog: sha=%s frameworks=%d rules=%d", c.SHA256, len(c.Frameworks), len(c.RuleIDs()))
	}
	if !strings.Contains(c.Notice, "not certification") {
		t.Error("catalog must carry the no-certification notice")
	}
	for _, m := range c.Mappings {
		if f, _ := c.Framework(m.Framework); f.Official && m.ReviewStatus == "reviewed" {
			t.Errorf("%s -> %s/%s marked reviewed; official-framework mappings stay unreviewed until checked against the source text",
				m.Rule, m.Framework, m.Control)
		}
	}
}

func TestParseCatalogRejectsBrokenReferences(t *testing.T) {
	base := `{"catalog_version":"x","notice":"n","frameworks":[{"id":"f","name":"F","version":"1","official":false,"source_url":"","controls":[{"id":"C1","title":"t"}]}],
	"rules":[{"id":"R1","title":"t","severity":"high","applies_to":{"terraform":["aws_x"],"inventory":[]},"remediation":"r"}],"mappings":[%s]}`
	for name, mapping := range map[string]string{
		"unknown rule":    `{"rule":"R9","framework":"f","control":"C1","coverage":"full","review_status":"reviewed","rationale":"x"}`,
		"unknown control": `{"rule":"R1","framework":"f","control":"C9","coverage":"full","review_status":"reviewed","rationale":"x"}`,
		"bad coverage":    `{"rule":"R1","framework":"f","control":"C1","coverage":"most","review_status":"reviewed","rationale":"x"}`,
		"no rationale":    `{"rule":"R1","framework":"f","control":"C1","coverage":"full","review_status":"reviewed","rationale":" "}`,
		"duplicate":       `{"rule":"R1","framework":"f","control":"C1","coverage":"full","review_status":"reviewed","rationale":"x"},{"rule":"R1","framework":"f","control":"C1","coverage":"full","review_status":"reviewed","rationale":"x"}`,
	} {
		if _, err := ParseCatalog([]byte(strings.Replace(base, "%s", mapping, 1))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseCatalog([]byte(`{"surprise":1}`)); err == nil {
		t.Error("unknown fields accepted")
	}
}

// Every rule ID used in the Rego policies must be in the catalog, and every
// catalog rule must be implemented by at least one policy.
func TestCatalogMatchesRegoPolicies(t *testing.T) {
	ruleRe := regexp.MustCompile(`"(AEGIS-[A-Z0-9]+-[0-9]{3})"`)
	inRego := map[string]bool{}
	err := filepath.WalkDir("../../policies", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".rego") || strings.HasSuffix(p, "_test.rego") {
			return err
		}
		b, err := os.ReadFile(p)
		for _, m := range ruleRe.FindAllStringSubmatch(string(b), -1) {
			inRego[m[1]] = true
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	c := cat(t)
	for id := range inRego {
		if _, ok := c.Rule(id); !ok {
			t.Errorf("rule %s used in Rego but missing from catalog", id)
		}
	}
	for _, id := range c.RuleIDs() {
		if !inRego[id] {
			t.Errorf("catalog rule %s is not implemented by any policy", id)
		}
	}
}

func TestApplies(t *testing.T) {
	c := cat(t)
	rule := func(id string) Rule { r, _ := c.Rule(id); return r }
	bucket := Subject{Kind: KindPlanned, Type: "aws_s3_bucket", Taggable: true, Region: "ap-south-1", Exists: true}
	pab := Subject{Kind: KindPlanned, Type: "aws_s3_bucket_public_access_block", Exists: true}
	deletedDB := Subject{Kind: KindPlanned, Type: "aws_db_instance", Exists: false}
	invBucket := Subject{Kind: KindInventory, Type: "storage.bucket", Region: "us-east-1", Exists: true}
	global := Subject{Kind: KindInventory, Type: "identity.role", Exists: true}

	cases := []struct {
		rule string
		s    Subject
		want bool
	}{
		{"AEGIS-S3-001", bucket, true},
		{"AEGIS-S3-001", pab, false},
		{"AEGIS-TAG-001", bucket, true},
		{"AEGIS-TAG-001", pab, false}, // not taggable
		{"AEGIS-REG-001", bucket, true},
		{"AEGIS-REG-001", pab, false}, // no region
		{"AEGIS-DB-001", deletedDB, false},
		{"AEGIS-TF-001", deletedDB, true},
		{"AEGIS-TF-001", bucket, true},
		{"AEGIS-S3-001", invBucket, true},
		{"AEGIS-TF-001", invBucket, false},
		{"AEGIS-TAG-001", global, true},
		{"AEGIS-REG-001", global, false},
	}
	for _, tc := range cases {
		if got := Applies(rule(tc.rule), tc.s); got != tc.want {
			t.Errorf("%s on %s(%s): got %v want %v", tc.rule, tc.s.Type, tc.s.Kind, got, tc.want)
		}
	}
}

func TestEvaluateWithExceptions(t *testing.T) {
	c := cat(t)
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	subjects := []Subject{
		{Kind: KindInventory, Label: "b1", Type: "storage.bucket", Exists: true},
		{Kind: KindInventory, Label: "b2", Type: "storage.bucket", Exists: true},
		{Kind: KindInventory, Label: "b3", Type: "storage.bucket", Exists: true},
	}
	findings := []PolicyFinding{
		{RuleID: "AEGIS-S3-001", Subject: "b1", Message: "public"},
		{RuleID: "AEGIS-S3-001", Subject: "b2", Message: "public"},
		{RuleID: "AEGIS-S3-001", Subject: "b3", Message: "public"},
		{RuleID: "AEGIS-S3-001", Subject: "b3", Message: "dup"},
		{RuleID: "AEGIS-NET-001", Subject: "ghost", Message: "unknown subject"},
	}
	exs := []Exception{
		{ID: "ok", RuleID: "AEGIS-S3-001", Subject: "b1", Status: "approved", ExpiresAt: now.Add(time.Hour)},
		{ID: "expired", RuleID: "AEGIS-S3-001", Subject: "b2", Status: "approved", ExpiresAt: now.Add(-time.Hour)},
		{ID: "pending", RuleID: "AEGIS-S3-001", Subject: "b3", Status: "requested", ExpiresAt: now.Add(time.Hour)},
	}
	evs := Evaluate(c, subjects, findings, exs, now)
	get := func(rule, subject string) Evaluation {
		for _, e := range evs {
			if e.RuleID == rule && e.Subject == subject {
				return e
			}
		}
		t.Fatalf("missing evaluation %s/%s", rule, subject)
		return Evaluation{}
	}
	if e := get("AEGIS-S3-001", "b1"); e.Result != ResultExcepted || e.ExceptionID != "ok" {
		t.Errorf("approved exception not applied: %+v", e)
	}
	if get("AEGIS-S3-001", "b2").Result != ResultFail {
		t.Error("expired exception applied")
	}
	if get("AEGIS-S3-001", "b3").Result != ResultFail {
		t.Error("unapproved exception applied")
	}
	if get("AEGIS-ENC-001", "b1").Result != ResultPass {
		t.Error("applicable rule without a finding must pass")
	}
	if get("AEGIS-NET-001", "ghost").Result != ResultFail {
		t.Error("finding on an unknown subject was dropped")
	}
	// 3 buckets x (S3-001, ENC-001, S3-002, TAG-001) + ghost
	if len(evs) != 13 {
		t.Errorf("got %d evaluations", len(evs))
	}
	pass, fail, exc := Tally(evs)
	if pass != 9 || fail != 3 || exc != 1 {
		t.Errorf("tally %d/%d/%d", pass, fail, exc)
	}
	if !slices.IsSortedFunc(evs, func(a, b Evaluation) int { return strings.Compare(a.RuleID+a.Subject, b.RuleID+b.Subject) }) {
		t.Error("evaluations not sorted")
	}
}

func TestWildcardExceptionAppliesToAllSubjects(t *testing.T) {
	c := cat(t)
	now := time.Now()
	evs := Evaluate(c,
		[]Subject{{Kind: KindInventory, Label: "v", Type: "network.vpc", Exists: true}},
		[]PolicyFinding{{RuleID: "AEGIS-TAG-001", Subject: "v"}},
		[]Exception{{ID: "w", RuleID: "AEGIS-TAG-001", Subject: "*", Status: "approved", ExpiresAt: now.Add(time.Hour)}}, now)
	if len(evs) != 1 || evs[0].Result != ResultExcepted {
		t.Fatalf("wildcard: %+v", evs)
	}
}
