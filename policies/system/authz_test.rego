package system.authz_test

import rego.v1

import data.system.authz

rt := {"env": {"OPA_AUTH_TOKEN": "s3cret"}}

test_health_is_anonymous if {
	authz.allow with input as {"method": "GET", "path": ["health"]}
		with opa.runtime as rt
}

test_evaluation_with_token if {
	authz.allow with input as {"method": "POST", "path": ["v1", "data", "aegis", "inventory"], "identity": "s3cret"}
		with opa.runtime as rt
}

test_bundle_listing_with_token if {
	authz.allow with input as {"method": "GET", "path": ["v1", "policies"], "identity": "s3cret"}
		with opa.runtime as rt
}

test_no_or_wrong_token_denied if {
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "aegis", "inventory"]}
		with opa.runtime as rt
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "aegis", "inventory"], "identity": "guess"}
		with opa.runtime as rt
}

test_policy_writes_denied_even_with_token if {
	not authz.allow with input as {"method": "PUT", "path": ["v1", "policies", "aws", "inventory.rego"], "identity": "s3cret"}
		with opa.runtime as rt
	not authz.allow with input as {"method": "DELETE", "path": ["v1", "policies", "aws", "inventory.rego"], "identity": "s3cret"}
		with opa.runtime as rt
	not authz.allow with input as {"method": "PUT", "path": ["v1", "data", "aegis", "inventory"], "identity": "s3cret"}
		with opa.runtime as rt
	not authz.allow with input as {"method": "PATCH", "path": ["v1", "data"], "identity": "s3cret"}
		with opa.runtime as rt
}

test_other_documents_denied if {
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "system", "authz"], "identity": "s3cret"}
		with opa.runtime as rt
	not authz.allow with input as {"method": "POST", "path": ["v1", "query"], "identity": "s3cret"}
		with opa.runtime as rt
	not authz.allow with input as {"method": "POST", "path": ["v1", "compile"], "identity": "s3cret"}
		with opa.runtime as rt
}

test_unset_token_denies_everything_but_health if {
	not authz.allow with input as {"method": "POST", "path": ["v1", "data", "aegis", "inventory"], "identity": ""}
		with opa.runtime as {"env": {}}
}
