package aegis.aws.storage_test

import rego.v1

import data.aegis.aws.storage

secure_bucket := {
	"resource_id": "aws_s3_bucket.logs",
	"resource_type": "storage.bucket",
	"configuration": {"public_access_block": true, "encryption": "aws:kms", "versioning": true},
}

rule_ids(findings) := {f.rule_id | some f in findings}

test_secure_bucket_passes if {
	count(storage.deny) == 0 with input as secure_bucket
	count(storage.warn) == 0 with input as secure_bucket
}

test_public_bucket_denied if {
	b := json.patch(secure_bucket, [{"op": "replace", "path": "/configuration/public_access_block", "value": false}])
	rule_ids(storage.deny) == {"AEGIS-S3-001"} with input as b
}

test_missing_public_access_block_denied if {
	b := json.remove(secure_bucket, ["configuration/public_access_block"])
	"AEGIS-S3-001" in rule_ids(storage.deny) with input as b
}

test_unencrypted_bucket_denied if {
	b := json.remove(secure_bucket, ["configuration/encryption"])
	rule_ids(storage.deny) == {"AEGIS-ENC-001"} with input as b
}

test_unknown_encryption_denied if {
	b := json.patch(secure_bucket, [{"op": "replace", "path": "/configuration/encryption", "value": "none"}])
	"AEGIS-ENC-001" in rule_ids(storage.deny) with input as b
}

test_versioning_disabled_warns if {
	b := json.patch(secure_bucket, [{"op": "replace", "path": "/configuration/versioning", "value": false}])
	rule_ids(storage.warn) == {"AEGIS-S3-002"} with input as b
	count(storage.deny) == 0 with input as b
}

test_non_bucket_ignored if {
	r := {"resource_id": "aws_instance.web", "resource_type": "compute.instance", "configuration": {}}
	count(storage.deny) == 0 with input as r
	count(storage.warn) == 0 with input as r
}
