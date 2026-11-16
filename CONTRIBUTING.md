# Contributing

1. Every change needs tests: unit tests, plus integration and failure/edge-case
   tests where relevant.
2. Run the checks before pushing (see [docs/getting-started.md](docs/getting-started.md#4-run-the-tests)).
3. Record significant architecture choices as an ADR in
   `architecture/architecture-decisions/` using the template.
4. Never commit secrets, real cloud credentials, Terraform state or unredacted
   plan JSON.
5. Never edit an applied migration — add a new one.
6. Do not report benchmark or test results that were not actually produced by
   the documented commands.

Commit messages: imperative mood, short subject line (e.g. `Add inventory import endpoint`).
