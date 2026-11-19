# METADATA
# title: Aegis observed-inventory policies
# description: |
#   Deterministic checks over normalised Aegis inventory resources (observed
#   state). Rule IDs match the Terraform plan policies so planned and observed
#   evidence map to the same compliance controls.
#   Input: {"resources": [{"id", "type", "region", "tags", "configuration"}], "config": {...}}
package aegis.inventory

import rego.v1

default_config := {
	"approved_regions": ["ap-south-1", "us-east-1", "eu-west-1"],
	"required_tags": ["owner", "environment", "cost_center"],
	"admin_ports": [22, 3389],
	"approved_encryption": ["AES256", "aws:kms", "aws:kms:dsse"],
}

config := object.union(default_config, object.get(input, "config", {}))

finding(rule_id, severity, r, message) := {
	"rule_id": rule_id,
	"severity": severity,
	"address": r.id,
	"resource_type": r.type,
	"message": message,
}

cfg(r) := object.get(r, "configuration", {})

# ---------------------------------------------------------------- storage

deny contains f if {
	some r in input.resources
	r.type == "storage.bucket"
	not cfg(r).public_access_block == true
	f := finding("AEGIS-S3-001", "high", r, "bucket does not block public access")
}

deny contains f if {
	some r in input.resources
	r.type == "storage.bucket"
	not encrypted(r)
	f := finding("AEGIS-ENC-001", "medium", r, "bucket has no approved server-side encryption")
}

encrypted(r) if cfg(r).encryption in config.approved_encryption

warn contains f if {
	some r in input.resources
	r.type == "storage.bucket"
	not cfg(r).versioning == true
	f := finding("AEGIS-S3-002", "medium", r, "bucket versioning is disabled")
}

# --------------------------------------------------------------- database

deny contains f if {
	some r in input.resources
	r.type == "database.instance"
	not cfg(r).storage_encrypted == true
	f := finding("AEGIS-DB-001", "high", r, "database storage is not encrypted at rest")
}

deny contains f if {
	some r in input.resources
	r.type == "database.instance"
	cfg(r).publicly_accessible == true
	f := finding("AEGIS-DB-002", "critical", r, "database is publicly accessible")
}

# -------------------------------------------------------------------- IAM

as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

deny contains f if {
	some r in input.resources
	r.type == "identity.policy"
	some s in object.get(cfg(r), "statements", [])
	lower(s.effect) == "allow"
	"*" in as_list(s.actions)
	"*" in as_list(s.resources)
	f := finding("AEGIS-IAM-001", "critical", r, "policy grants all actions on all resources")
}

# ---------------------------------------------------------------- network

net_rule("0.0.0.0/0") := "AEGIS-NET-001"

net_rule("::/0") := "AEGIS-NET-002"

covers_admin_port(rule) if rule.protocol in {"-1", "all"}

covers_admin_port(rule) if {
	rule.protocol in {"tcp", "6"}
	some port in config.admin_ports
	rule.from_port <= port
	port <= rule.to_port
}

deny contains f if {
	some r in input.resources
	r.type == "network.security_group"
	some rule in object.get(cfg(r), "ingress", [])
	some cidr in array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))
	cidr in {"0.0.0.0/0", "::/0"}
	covers_admin_port(rule)
	f := finding(net_rule(cidr), "critical", r, sprintf("administrative port open to %s", [cidr]))
}

# ---------------------------------------------------------------- logging

deny contains f if {
	some r in input.resources
	r.type == "logging.trail"
	not trail_ok(cfg(r))
	f := finding("AEGIS-LOG-001", "high", r, "CloudTrail logging or log file validation is disabled")
}

trail_ok(c) if {
	c.enable_logging == true
	c.log_file_validation == true
}

# ---------------------------------------------------------- tags / region

warn contains f if {
	some r in input.resources
	missing := [t | some t in config.required_tags; not tag_set(object.get(r, "tags", {}), t)]
	count(missing) > 0
	f := finding("AEGIS-TAG-001", "medium", r, sprintf("missing required tags: %s", [concat(", ", missing)]))
}

deny contains f if {
	some r in input.resources
	object.get(r, "region", "") != ""
	not r.region in config.approved_regions
	f := finding("AEGIS-REG-001", "high", r, sprintf("region %s is not approved", [r.region]))
}

# A blank tag value does not count as set.
tag_set(tags, t) if trim_space(tags[t]) != ""
