# METADATA
# title: Aegis Terraform plan policies
# description: |
#   Deterministic checks over the Aegis-normalised view of a Terraform plan.
#   Input: {"resources": [PlannedResource...], "config": {...optional overrides}}
#   Output: deny (blocking) and warn (advisory) sets of findings.
package aegis.terraform

import rego.v1

default_config := {
	"approved_regions": ["ap-south-1", "us-east-1", "eu-west-1"],
	"required_tags": ["owner", "environment", "cost_center"],
	"stateful_types": [
		"aws_db_instance", "aws_rds_cluster", "aws_s3_bucket", "aws_dynamodb_table",
		"aws_kms_key", "aws_efs_file_system", "aws_ebs_volume",
	],
	"admin_ports": [22, 3389],
}

config := object.union(default_config, object.get(input, "config", {}))

finding(rule_id, severity, r, message) := {
	"rule_id": rule_id,
	"severity": severity,
	"address": r.address,
	"resource_type": r.type,
	"message": message,
}

# Resources that will exist after apply.
live contains r if {
	some r in input.resources
	r.action != "delete"
	r.after != null
}

# ---------------------------------------------------------------- storage

buckets contains b if {
	some b in live
	b.type == "aws_s3_bucket"
}

public_access_blocked(b) if {
	pab := b.linked.aws_s3_bucket_public_access_block
	pab.block_public_acls == true
	pab.block_public_policy == true
	pab.ignore_public_acls == true
	pab.restrict_public_buckets == true
}

deny contains f if {
	some b in buckets
	not public_access_blocked(b)
	f := finding("AEGIS-S3-001", "high", b, "S3 bucket does not block all public access (missing or permissive public access block)")
}

deny contains f if {
	some b in buckets
	not b.linked.aws_s3_bucket_server_side_encryption_configuration
	f := finding("AEGIS-ENC-001", "medium", b, "S3 bucket has no explicit server-side encryption configuration")
}

versioning_enabled(b) if {
	some vc in b.linked.aws_s3_bucket_versioning.versioning_configuration
	vc.status == "Enabled"
}

warn contains f if {
	some b in buckets
	not versioning_enabled(b)
	f := finding("AEGIS-S3-002", "medium", b, "S3 bucket versioning is not enabled")
}

# --------------------------------------------------------------- database

databases contains d if {
	some d in live
	d.type in {"aws_db_instance", "aws_rds_cluster"}
}

deny contains f if {
	some d in databases
	not d.after.storage_encrypted == true
	f := finding("AEGIS-DB-001", "high", d, "database storage is not encrypted at rest")
}

deny contains f if {
	some d in databases
	d.after.publicly_accessible == true
	f := finding("AEGIS-DB-002", "critical", d, "database instance is publicly accessible")
}

# -------------------------------------------------------------------- IAM

policy_types := {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

statements(doc) := as_list(doc.Statement)

full_admin(stmt) if {
	stmt.Effect == "Allow"
	"*" in as_list(stmt.Action)
	"*" in as_list(stmt.Resource)
}

deny contains f if {
	some p in live
	p.type in policy_types
	is_string(p.after.policy)
	doc := json.unmarshal(p.after.policy)
	some stmt in statements(doc)
	full_admin(stmt)
	f := finding("AEGIS-IAM-001", "critical", p, "IAM policy grants all actions on all resources (Action \"*\", Resource \"*\")")
}

# ---------------------------------------------------------------- network

open_cidrs := {"0.0.0.0/0", "::/0"}

covers_admin_port(protocol, _, _) if {
	protocol in {"-1", "all"}
}

covers_admin_port(protocol, from, to) if {
	protocol in {"tcp", "6"}
	some port in config.admin_ports
	from <= port
	port <= to
}

# Inline ingress blocks on aws_security_group.
deny contains f if {
	some sg in live
	sg.type == "aws_security_group"
	some rule in sg.after.ingress
	some cidr in array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))
	cidr in open_cidrs
	covers_admin_port(rule.protocol, rule.from_port, rule.to_port)
	f := finding("AEGIS-NET-001", "critical", sg, sprintf("security group allows administrative access (ports %v) from %s", [config.admin_ports, cidr]))
}

# Standalone ingress rule resources.
deny contains f if {
	some r in live
	r.type == "aws_vpc_security_group_ingress_rule"
	some cidr in [object.get(r.after, "cidr_ipv4", ""), object.get(r.after, "cidr_ipv6", "")]
	cidr in open_cidrs
	covers_admin_port(r.after.ip_protocol, object.get(r.after, "from_port", 0), object.get(r.after, "to_port", 65535))
	f := finding("AEGIS-NET-001", "critical", r, sprintf("ingress rule allows administrative access (ports %v) from %s", [config.admin_ports, cidr]))
}

deny contains f if {
	some r in live
	r.type == "aws_security_group_rule"
	r.after.type == "ingress"
	some cidr in array.concat(object.get(r.after, "cidr_blocks", []), object.get(r.after, "ipv6_cidr_blocks", []))
	cidr in open_cidrs
	covers_admin_port(r.after.protocol, r.after.from_port, r.after.to_port)
	f := finding("AEGIS-NET-001", "critical", r, sprintf("security group rule allows administrative access (ports %v) from %s", [config.admin_ports, cidr]))
}

# ---------------------------------------------------------------- logging

deny contains f if {
	some t in live
	t.type == "aws_cloudtrail"
	problems := [msg |
		some check in [
			{"ok": t.after.enable_logging != false, "msg": "logging is disabled"},
			{"ok": t.after.enable_log_file_validation == true, "msg": "log file validation is disabled"},
		]
		not check.ok
		msg := check.msg
	]
	count(problems) > 0
	f := finding("AEGIS-LOG-001", "high", t, sprintf("CloudTrail %s", [concat(" and ", problems)]))
}

# ---------------------------------------------------------- tags / region

warn contains f if {
	some r in live
	r.taggable
	missing := [t | some t in config.required_tags; not r.tags[t]]
	count(missing) > 0
	f := finding("AEGIS-TAG-001", "medium", r, sprintf("missing required tags: %s", [concat(", ", missing)]))
}

deny contains f if {
	some r in live
	r.region != ""
	not r.region in config.approved_regions
	f := finding("AEGIS-REG-001", "high", r, sprintf("region %s is not in the approved list %v", [r.region, config.approved_regions]))
}

# ----------------------------------------------------- destructive change

deny contains f if {
	some r in input.resources
	r.destructive
	r.type in config.stateful_types
	f := finding("AEGIS-TF-001", "high", r, sprintf("plan will %s stateful resource (data loss risk); requires explicit approval", [r.action]))
}
