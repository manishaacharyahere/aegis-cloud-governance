# METADATA
# title: OPA API authorization
# description: |
#   Loaded with `opa run --server --authentication=token --authorization=basic`.
#   Policies are mounted read-only and can never be changed through the API:
#   only evaluation of the aegis packages and listing of policies (for the
#   bundle hash) are allowed, and only with the token in OPA_AUTH_TOKEN.
#   Health checks are anonymous. With no token configured, everything else is
#   denied (fail closed).
package system.authz

import rego.v1

default allow := false

token := object.get(opa.runtime(), ["env", "OPA_AUTH_TOKEN"], "")

allow if {
	input.method == "GET"
	input.path == ["health"]
}

allow if {
	token != ""
	input.identity == token
	read_only
}

# Evaluate a document under data.aegis (POST with input, or GET).
read_only if {
	input.method in {"GET", "POST"}
	input.path[0] == "v1"
	input.path[1] == "data"
	input.path[2] == "aegis"
}

# List policy modules, used to hash the loaded policy text.
read_only if {
	input.method == "GET"
	input.path == ["v1", "policies"]
}
