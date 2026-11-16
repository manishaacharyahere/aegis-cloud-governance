package iac

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadPlan(t *testing.T, fixture string) *Plan {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", fixture+".plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p, err := ParsePlan(f)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func find(a Analysis, addr string) PlannedResource {
	for _, r := range a.Resources {
		if r.Address == addr {
			return r
		}
	}
	return PlannedResource{}
}

func TestParsePlanRejectsBadInput(t *testing.T) {
	for name, body := range map[string]string{
		"not json":       "{",
		"wrong format":   `{"format_version":"0.2"}`,
		"errored":        `{"format_version":"1.2","errored":true}`,
		"missing format": `{}`,
	} {
		if _, err := ParsePlan(strings.NewReader(body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestAnalyzeGoldenPlans(t *testing.T) {
	a := Analyze(loadPlan(t, "insecure-storage"))
	if a.Summary.Create != 4 || len(a.Resources) != 4 {
		t.Fatalf("summary %+v, %d resources", a.Summary, len(a.Resources))
	}
	b := find(a, "aws_s3_bucket.public_assets")
	if b.Region != "ap-south-1" || b.Action != ActionCreate || b.Destructive {
		t.Errorf("bucket: %+v", b)
	}
	pab, ok := b.Linked["aws_s3_bucket_public_access_block"]
	if !ok || pab["block_public_acls"] != false {
		t.Errorf("public access block not linked: %+v", b.Linked)
	}
	if ex := find(a, "aws_s3_bucket.exports"); len(ex.Linked) != 0 {
		t.Errorf("exports should have no companions: %+v", ex.Linked)
	}
	if !b.Taggable || b.Tags["owner"] != "payments-team" {
		t.Errorf("default tags not applied: %+v", b.Tags)
	}

	sec := Analyze(loadPlan(t, "secure-baseline"))
	sb := find(sec, "aws_s3_bucket.customer_data")
	for _, c := range []string{"aws_s3_bucket_public_access_block", "aws_s3_bucket_server_side_encryption_configuration", "aws_s3_bucket_versioning"} {
		if _, ok := sb.Linked[c]; !ok {
			t.Errorf("secure bucket missing linked %s", c)
		}
	}
	if pab := find(sec, "aws_s3_bucket_public_access_block.customer_data"); pab.Taggable {
		t.Error("public access block is not taggable")
	}
}

func TestEffectiveTagsWhenTagsAllUnknown(t *testing.T) {
	a := Analyze(loadPlan(t, "missing-logging-tags"))
	trail := find(a, "aws_cloudtrail.disabled")
	if !trail.Taggable || len(trail.Tags) != 0 {
		t.Errorf("trail tags: taggable=%v %v", trail.Taggable, trail.Tags)
	}
	if b := find(a, "aws_s3_bucket.trail_logs"); b.Tags["environment"] != "staging" || b.Tags["owner"] != "" {
		t.Errorf("bucket tags: %v", b.Tags)
	}
}

func TestRegionFromProvider(t *testing.T) {
	if r := find(Analyze(loadPlan(t, "unapproved-region")), "aws_vpc.shadow"); r.Region != "sa-east-1" {
		t.Errorf("region = %q", r.Region)
	}
}

func TestClassifyActions(t *testing.T) {
	for in, want := range map[string]Action{
		"create": ActionCreate, "update": ActionUpdate, "delete": ActionDelete,
		"delete,create": ActionReplace, "create,delete": ActionReplace, "read": ActionRead, "no-op": ActionNoOp,
	} {
		if got := classify(strings.Split(in, ",")); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}

func TestRedactionUsesSensitiveMaskAndKeyNames(t *testing.T) {
	plan := `{"format_version":"1.2","resource_changes":[{"address":"aws_db_instance.x","mode":"managed","type":"aws_db_instance","name":"x",
	 "change":{"actions":["delete","create"],
	  "before":{"password":"old-secret","engine":"postgres","nested":{"api_key":"k1"}},
	  "after":{"password":"new-secret","engine":"postgres","config":{"conn":"postgres://u:p@h"},"manage_master_user_password":true},
	  "before_sensitive":{"password":true},
	  "after_sensitive":{"config":{"conn":true}}}}]}`
	p, err := ParsePlan(strings.NewReader(plan))
	if err != nil {
		t.Fatal(err)
	}
	a := Analyze(p)
	raw, _ := json.Marshal(a)
	for _, secret := range []string{"old-secret", "new-secret", "k1", "u:p@h"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("secret %q leaked: %s", secret, raw)
		}
	}
	r := a.Resources[0]
	if r.Action != ActionReplace || !r.Destructive {
		t.Errorf("replace not detected: %+v", r)
	}
	if r.After["manage_master_user_password"] != true {
		t.Error("boolean flags with secret-like names must be kept (they are not secrets)")
	}
	if len(a.RedactedPaths) != 4 {
		t.Errorf("redacted paths = %v", a.RedactedPaths)
	}
}

func TestDataSourcesIgnored(t *testing.T) {
	p, _ := ParsePlan(strings.NewReader(`{"format_version":"1.2","resource_changes":[
		{"address":"data.aws_caller_identity.me","mode":"data","type":"aws_caller_identity","change":{"actions":["read"]}}]}`))
	if a := Analyze(p); len(a.Resources) != 0 {
		t.Fatalf("data source treated as resource: %+v", a.Resources)
	}
}
