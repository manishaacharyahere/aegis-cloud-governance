package aegis.inventory_test

import rego.v1

import data.aegis.inventory

tags := {"owner": "t", "environment": "production", "cost_center": "c"}

r(type, cfg) := {"id": sprintf("%s.x", [type]), "type": type, "region": "ap-south-1", "tags": tags, "configuration": cfg}

ids(fs) := {f.rule_id | some f in fs}

evaluate(res) := result if {
	result := ids(inventory.deny | inventory.warn) with input as {"resources": [res]}
}

test_secure_bucket if {
	evaluate(r("storage.bucket", {"public_access_block": true, "encryption": "aws:kms", "versioning": true})) == set()
}

test_insecure_bucket if {
	evaluate(r("storage.bucket", {"public_access_block": false})) == {"AEGIS-S3-001", "AEGIS-ENC-001", "AEGIS-S3-002"}
}

test_database if {
	evaluate(r("database.instance", {"storage_encrypted": false, "publicly_accessible": true})) == {"AEGIS-DB-001", "AEGIS-DB-002"}
	evaluate(r("database.instance", {"storage_encrypted": true, "publicly_accessible": false})) == set()
}

test_iam if {
	evaluate(r("identity.policy", {"statements": [{"effect": "Allow", "actions": ["*"], "resources": ["*"]}]})) == {"AEGIS-IAM-001"}
	evaluate(r("identity.policy", {"statements": [{"effect": "Allow", "actions": ["s3:GetObject"], "resources": ["*"]}]})) == set()
	evaluate(r("identity.policy", {"statements": [{"effect": "Deny", "actions": ["*"], "resources": ["*"]}]})) == set()
}

test_network if {
	ssh := {"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}
	https := {"protocol": "tcp", "from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}
	evaluate(r("network.security_group", {"ingress": [https, ssh]})) == {"AEGIS-NET-001"}
	evaluate(r("network.security_group", {"ingress": [https]})) == set()
	rdp6 := {"protocol": "tcp", "from_port": 3389, "to_port": 3389, "ipv6_cidr_blocks": ["::/0"]}
	evaluate(r("network.security_group", {"ingress": [rdp6]})) == {"AEGIS-NET-002"}
}

test_trail if {
	evaluate(r("logging.trail", {"enable_logging": false, "log_file_validation": true})) == {"AEGIS-LOG-001"}
	evaluate(r("logging.trail", {"enable_logging": true, "log_file_validation": true})) == set()
}

test_tags_and_region if {
	untagged := json.patch(r("network.vpc", {}), [{"op": "replace", "path": "/tags", "value": {}}])
	evaluate(untagged) == {"AEGIS-TAG-001"}
	far := json.patch(r("network.vpc", {}), [{"op": "replace", "path": "/region", "value": "sa-east-1"}])
	evaluate(far) == {"AEGIS-REG-001"}
	global := json.patch(r("identity.role", {}), [{"op": "replace", "path": "/region", "value": ""}])
	evaluate(global) == set()
}
