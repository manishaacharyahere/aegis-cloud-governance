// Module boundary: keeps apps/web (and its node_modules) out of the root
// Go module, so "go test ./..." and govulncheck never scan npm packages.
module github.com/manishaacharyahere/aegis-cloud-governance/apps/web

go 1.27
