package opa

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func server(t *testing.T, policies string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/policies":
			fmt.Fprint(w, policies)
		case "/v1/data/aegis/x":
			fmt.Fprint(w, `{"result":{"deny":[1]}}`)
		case "/v1/data/aegis/missing":
			fmt.Fprint(w, `{}`)
		case "/v1/data/aegis/boom":
			w.WriteHeader(500)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return &Client{BaseURL: srv.URL}
}

func TestQuery(t *testing.T) {
	c := server(t, "")
	var out struct{ Deny []int }
	if err := c.Query(context.Background(), "aegis.x", map[string]any{}, &out); err != nil || len(out.Deny) != 1 {
		t.Fatalf("query: %v %+v", err, out)
	}
	if err := c.Query(context.Background(), "aegis.missing", nil, &out); !errors.Is(err, ErrUndefined) {
		t.Errorf("undefined: %v", err)
	}
	var u *UnavailableError
	if err := c.Query(context.Background(), "aegis.boom", nil, &out); !errors.As(err, &u) {
		t.Errorf("5xx should be UnavailableError: %v", err)
	}
	if err := c.Query(context.Background(), "aegis.nope", nil, &out); err == nil || errors.As(err, &u) {
		t.Errorf("404 should be a permanent error: %v", err)
	}
}

func TestBundleHashIgnoresTestsOrderAndPaths(t *testing.T) {
	a := server(t, `{"result":[{"id":"/policies/a.rego","raw":"package a"},{"id":"/policies/b.rego","raw":"package b"},{"id":"/policies/a_test.rego","raw":"package a_test"}]}`)
	b := server(t, `{"result":[{"id":"/mnt/b.rego","raw":"package b"},{"id":"/mnt/a.rego","raw":"package a"}]}`)
	c := server(t, `{"result":[{"id":"/policies/a.rego","raw":"package a\n"},{"id":"/policies/b.rego","raw":"package b"}]}`)
	ba, _ := a.Bundle(context.Background())
	bb, _ := b.Bundle(context.Background())
	bc, _ := c.Bundle(context.Background())
	if ba.SHA256 == "" || ba.SHA256 != bb.SHA256 || ba.SHA256 == bc.SHA256 {
		t.Fatalf("hashes: %s %s %s", ba.SHA256, bb.SHA256, bc.SHA256)
	}
	if len(ba.Modules) != 2 {
		t.Errorf("test modules should be excluded: %v", ba.Modules)
	}
	if _, err := server(t, `{"result":[]}`).Bundle(context.Background()); !errors.Is(err, ErrUndefined) {
		t.Errorf("empty bundle: %v", err)
	}
}
