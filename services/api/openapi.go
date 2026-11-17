package api

import (
	_ "embed"
	"net/http"
)

// openAPISpec is the API contract. TestOpenAPICoversRoutes fails when a
// route or its permission is missing from it.
//
//go:embed openapi.yaml
var openAPISpec []byte

func serveOpenAPI(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(openAPISpec)
}
