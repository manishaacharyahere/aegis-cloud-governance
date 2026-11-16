# METADATA
# title: Aegis storage baseline
# description: Deterministic checks for normalised storage.bucket resources.
package aegis.aws.storage

import rego.v1

# Input: one normalised Aegis resource, e.g.
# {"resource_id": "...", "resource_type": "storage.bucket", "configuration": {...}}

is_bucket if input.resource_type == "storage.bucket"

deny contains finding if {
	is_bucket
	not input.configuration.public_access_block == true
	finding := {
		"rule_id": "AEGIS-S3-001",
		"severity": "high",
		"resource_id": input.resource_id,
		"message": "storage bucket does not block public access",
	}
}

deny contains finding if {
	is_bucket
	not encrypted
	finding := {
		"rule_id": "AEGIS-ENC-001",
		"severity": "high",
		"resource_id": input.resource_id,
		"message": "storage bucket is not encrypted at rest",
	}
}

warn contains finding if {
	is_bucket
	not input.configuration.versioning == true
	finding := {
		"rule_id": "AEGIS-S3-002",
		"severity": "medium",
		"resource_id": input.resource_id,
		"message": "storage bucket versioning is disabled",
	}
}

encrypted if input.configuration.encryption in {"AES256", "aws:kms", "aws:kms:dsse"}
