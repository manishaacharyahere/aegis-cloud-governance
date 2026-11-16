package aegis.terraform_test

import rego.v1

import data.aegis.terraform

tags := {"owner": "t", "environment": "production", "cost_center": "c"}

res(type, after) := {
	"address": sprintf("%s.x", [type]), "type": type, "action": "create", "destructive": false,
	"region": "ap-south-1", "taggable": true, "tags": tags, "after": after,
}

ids(findings) := {f.rule_id | some f in findings}

secure_bucket := object.union(res("aws_s3_bucket", {"bucket": "b"}), {"linked": {
	"aws_s3_bucket_public_access_block": {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true},
	"aws_s3_bucket_server_side_encryption_configuration": {"rule": []},
	"aws_s3_bucket_versioning": {"versioning_configuration": [{"status": "Enabled"}]},
}})

test_secure_bucket_clean if {
	count(terraform.deny) == 0 with input as {"resources": [secure_bucket]}
	count(terraform.warn) == 0 with input as {"resources": [secure_bucket]}
}

test_partial_public_access_block_denied if {
	b := json.patch(secure_bucket, [{"op": "replace", "path": "/linked/aws_s3_bucket_public_access_block/restrict_public_buckets", "value": false}])
	ids(terraform.deny) == {"AEGIS-S3-001"} with input as {"resources": [b]}
}

test_bare_bucket if {
	b := res("aws_s3_bucket", {"bucket": "b"})
	ids(terraform.deny) == {"AEGIS-S3-001", "AEGIS-ENC-001"} with input as {"resources": [b]}
	ids(terraform.warn) == {"AEGIS-S3-002"} with input as {"resources": [b]}
}

test_deleted_bucket_not_evaluated_for_config if {
	b := object.union(res("aws_s3_bucket", {"bucket": "b"}), {"action": "delete", "after": null})
	count(terraform.warn) == 0 with input as {"resources": [b]}
	not "AEGIS-S3-001" in ids(terraform.deny) with input as {"resources": [b]}
}

test_database_rules if {
	d := res("aws_db_instance", {"storage_encrypted": false, "publicly_accessible": true})
	ids(terraform.deny) == {"AEGIS-DB-001", "AEGIS-DB-002"} with input as {"resources": [d]}
	ok := res("aws_db_instance", {"storage_encrypted": true, "publicly_accessible": false})
	count(terraform.deny) == 0 with input as {"resources": [ok]}
}

test_iam_full_admin_string_and_list_forms if {
	p1 := res("aws_iam_policy", {"policy": `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`})
	p2 := res("aws_iam_policy", {"policy": `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","*"],"Resource":["*"]}]}`})
	ids(terraform.deny) == {"AEGIS-IAM-001"} with input as {"resources": [p1]}
	ids(terraform.deny) == {"AEGIS-IAM-001"} with input as {"resources": [p2]}
}

test_iam_scoped_or_deny_not_flagged if {
	scoped := res("aws_iam_policy", {"policy": `{"Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::b/*"]}]}`})
	denyall := res("aws_iam_policy", {"policy": `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`})
	unknown := res("aws_iam_policy", {"policy": null})
	count(terraform.deny) == 0 with input as {"resources": [scoped, denyall, unknown]}
}

sg(ingress) := res("aws_security_group", {"ingress": ingress})

rule(port_from, port_to, proto, cidr) := {"from_port": port_from, "to_port": port_to, "protocol": proto, "cidr_blocks": [cidr], "ipv6_cidr_blocks": []}

test_network_admin_ports if {
	ids(terraform.deny) == {"AEGIS-NET-001"} with input as {"resources": [sg([rule(22, 22, "tcp", "0.0.0.0/0")])]}
	ids(terraform.deny) == {"AEGIS-NET-001"} with input as {"resources": [sg([rule(0, 65535, "tcp", "0.0.0.0/0")])]}
	ids(terraform.deny) == {"AEGIS-NET-001"} with input as {"resources": [sg([rule(0, 0, "-1", "0.0.0.0/0")])]}
}

test_network_not_flagged if {
	count(terraform.deny) == 0 with input as {"resources": [sg([rule(443, 443, "tcp", "0.0.0.0/0")])]}
	count(terraform.deny) == 0 with input as {"resources": [sg([rule(22, 22, "tcp", "10.0.0.0/8")])]}
	count(terraform.deny) == 0 with input as {"resources": [sg([rule(22, 22, "udp", "0.0.0.0/0")])]}
}

test_standalone_ipv6_rule if {
	r := res("aws_vpc_security_group_ingress_rule", {"cidr_ipv6": "::/0", "ip_protocol": "tcp", "from_port": 3389, "to_port": 3389})
	ids(terraform.deny) == {"AEGIS-NET-001"} with input as {"resources": [r]}
}

test_cloudtrail if {
	bad := res("aws_cloudtrail", {"enable_logging": false, "enable_log_file_validation": false})
	ids(terraform.deny) == {"AEGIS-LOG-001"} with input as {"resources": [bad]}
	ok := res("aws_cloudtrail", {"enable_logging": true, "enable_log_file_validation": true})
	count(terraform.deny) == 0 with input as {"resources": [ok]}
}

test_missing_tags_warns if {
	r := json.patch(res("aws_vpc", {}), [{"op": "replace", "path": "/tags", "value": {"environment": "dev"}}])
	ids(terraform.warn) == {"AEGIS-TAG-001"} with input as {"resources": [r]}
	untaggable := object.union(r, {"taggable": false})
	count(terraform.warn) == 0 with input as {"resources": [untaggable]}
}

test_region if {
	r := object.union(res("aws_vpc", {}), {"region": "sa-east-1"})
	ids(terraform.deny) == {"AEGIS-REG-001"} with input as {"resources": [r]}
	count(terraform.deny) == 0 with input as {"resources": [r], "config": {"approved_regions": ["sa-east-1"]}}
}

test_destructive_stateful_change if {
	r := object.union(res("aws_db_instance", {"storage_encrypted": true}), {"action": "replace", "destructive": true})
	ids(terraform.deny) == {"AEGIS-TF-001"} with input as {"resources": [r]}
	stateless := object.union(res("aws_security_group", {"ingress": []}), {"action": "delete", "destructive": true, "after": null})
	count(terraform.deny) == 0 with input as {"resources": [stateless]}
}
