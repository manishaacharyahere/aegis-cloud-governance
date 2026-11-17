package api

import (
	"bufio"
	"bytes"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// specOperations reads "METHOD /path" -> x-aegis-permission from the spec.
// The spec is block-style YAML with two-space indentation (paths at depth 1,
// methods at depth 2), which this line reader relies on.
func specOperations(t *testing.T) map[string]string {
	t.Helper()
	pathRe := regexp.MustCompile(`^  (/\S*):$`)
	methodRe := regexp.MustCompile(`^    (get|post|put|delete|patch):$`)
	permRe := regexp.MustCompile(`^      x-aegis-permission: (\w+)$`)
	ops := map[string]string{}
	var path, op string
	inPaths := false
	sc := bufio.NewScanner(bytes.NewReader(openAPISpec))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "paths:":
			inPaths = true
		case inPaths && len(line) > 0 && line[0] != ' ':
			inPaths = false
		case !inPaths:
		case pathRe.MatchString(line):
			path = pathRe.FindStringSubmatch(line)[1]
		case methodRe.MatchString(line):
			op = strings.ToUpper(methodRe.FindStringSubmatch(line)[1]) + " " + path
			ops[op] = ""
		case permRe.MatchString(line):
			ops[op] = permRe.FindStringSubmatch(line)[1]
		}
	}
	return ops
}

func TestOpenAPICoversRoutes(t *testing.T) {
	ops := specOperations(t)
	for route, perm := range routePermissions {
		got, ok := ops[route]
		if !ok {
			t.Errorf("%s is missing from openapi.yaml", route)
			continue
		}
		if got != string(perm) {
			t.Errorf("%s: spec says x-aegis-permission %q, routePermissions says %q", route, got, perm)
		}
	}
	for op := range ops {
		if _, ok := routePermissions[op]; !ok {
			t.Errorf("openapi.yaml documents %s, which is not a route", op)
		}
	}
}

func TestOpenAPIServed(t *testing.T) {
	h := NewHandler(Deps{})
	rec := do(h, "GET", "/api/v1/openapi.yaml", nil, nil)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/yaml") ||
		!bytes.Contains(rec.Body.Bytes(), []byte("openapi: 3.1.0")) {
		t.Fatalf("status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}
