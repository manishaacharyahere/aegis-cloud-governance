package inventory

import (
	"errors"
	"testing"
	"time"
)

const sampleState = `{
  "version": 4, "terraform_version": "1.9.8", "serial": 3, "lineage": "x",
  "resources": [
    {"mode": "managed", "type": "aws_kms_key", "name": "main",
     "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
     "instances": [{"attributes": {"id": "k1", "arn": "arn:aws:kms:eu-west-1:123456789012:key/k1",
        "enable_key_rotation": true, "tags": {"environment": "production", "owner": "platform"}},
        "sensitive_attributes": []}]},
    {"module": "module.data", "mode": "managed", "type": "aws_s3_bucket", "name": "logs",
     "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
     "instances": [{"index_key": "a", "attributes": {"id": "b-a", "arn": "arn:aws:s3:::b-a", "bucket": "b-a",
        "tags_all": {"x": "y"}, "secret_value": "s3cr3t", "policy": null},
        "sensitive_attributes": [[{"type": "get_attr", "value": "secret_value"}]],
        "dependencies": ["aws_kms_key.main", "aws_iam_role.gone"]},
       {"index_key": 1, "attributes": {"id": "b-1"}}]},
    {"mode": "data", "type": "aws_caller_identity", "name": "me",
     "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]", "instances": [{"attributes": {}}]},
    {"mode": "managed", "type": "random_id", "name": "r",
     "provider": "provider[\"registry.terraform.io/hashicorp/random\"]", "instances": [{"attributes": {}}]}
  ]}`

func TestFromTerraformState(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	snap, skipped, err := FromTerraformState([]byte(sampleState), StateOptions{CapturedAt: at, Environment: "staging"})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Source != "terraform_state" || snap.Account.ExternalID != "123456789012" || snap.Account.Name != "terraform-123456789012" {
		t.Fatalf("account/source: %+v %s", snap.Account, snap.Source)
	}
	if len(skipped) != 2 {
		t.Errorf("data source and non-AWS resource must be skipped: %v", skipped)
	}
	if len(snap.Resources) != 3 {
		t.Fatalf("resources = %d", len(snap.Resources))
	}
	byID := map[string]Resource{}
	for _, r := range snap.Resources {
		byID[r.ResourceID] = r
	}
	k := byID["aws_kms_key.main"]
	if k.Region != "eu-west-1" || k.Tags["owner"] != "platform" || k.Configuration["enable_key_rotation"] != true {
		t.Errorf("kms: %+v", k)
	}
	if _, ok := k.Configuration["arn"]; ok {
		t.Error("arn must not be copied into configuration")
	}
	b := byID[`module.data.aws_s3_bucket.logs["a"]`]
	if _, ok := b.Configuration["secret_value"]; ok {
		t.Error("attribute marked sensitive by Terraform must be dropped")
	}
	if _, ok := b.Configuration["policy"]; ok {
		t.Error("null attributes must be dropped")
	}
	if len(b.Relationships) != 1 || b.Relationships[0].TargetID != "aws_kms_key.main" {
		t.Errorf("only resolvable dependencies become edges: %+v", b.Relationships)
	}
	if b.Environment != "staging" {
		t.Errorf("default environment: %q", b.Environment)
	}
	if _, ok := byID["module.data.aws_s3_bucket.logs[1]"]; !ok {
		t.Error("numeric index keys")
	}
	if err := Validate(snap, at.Add(time.Minute)); err != nil {
		t.Fatalf("converted snapshot must validate: %v", err)
	}
}

func TestFromTerraformStateRejects(t *testing.T) {
	for _, in := range []string{`not json`, `{"version": 3, "resources": []}`} {
		if _, _, err := FromTerraformState([]byte(in), StateOptions{}); !errors.Is(err, ErrUnsupportedState) {
			t.Errorf("%q: %v", in, err)
		}
	}
}
