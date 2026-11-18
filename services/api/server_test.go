package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeDB struct{ err error }

func (f fakeDB) Ping(context.Context) error { return f.err }

func newTestHandler(t *testing.T, db Pinger, logs *bytes.Buffer) http.Handler {
	t.Helper()
	if logs == nil {
		logs = &bytes.Buffer{}
	}
	return NewHandler(Deps{
		Logger:       slog.New(slog.NewJSONHandler(logs, nil)),
		DB:           db,
		Version:      "test",
		MaxBodyBytes: 1024,
	})
}

func do(h http.Handler, method, path string, body io.Reader, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = "127.0.0.1:40000" // a local client, as in development
	req.Host = "localhost:8080"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLiveness(t *testing.T) {
	rec := do(newTestHandler(t, fakeDB{}, nil), http.MethodGet, "/healthz", nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("content-type = %q", ct)
	}
}

func TestReadiness(t *testing.T) {
	tests := []struct {
		name   string
		db     Pinger
		status int
		state  string
	}{
		{"healthy", fakeDB{}, http.StatusOK, "ok"},
		{"db down", fakeDB{err: errors.New("dial tcp: secret-host refused")}, http.StatusServiceUnavailable, "unavailable"},
		{"no db", nil, http.StatusServiceUnavailable, "unconfigured"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(newTestHandler(t, tt.db, nil), http.MethodGet, "/readyz", nil, nil)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			var body struct {
				Checks map[string]string `json:"checks"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Checks["database"] != tt.state {
				t.Errorf("database check = %q, want %q", body.Checks["database"], tt.state)
			}
			if strings.Contains(rec.Body.String(), "secret-host") {
				t.Error("readiness response leaks internal error details")
			}
		})
	}
}

func TestMethodAndRouteHandling(t *testing.T) {
	h := newTestHandler(t, fakeDB{}, nil)
	if rec := do(h, http.MethodPost, "/healthz", nil, nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz = %d, want 405", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/nope", nil, nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown route = %d, want 404", rec.Code)
	}
}

func TestRequestIDPropagationAndSanitisation(t *testing.T) {
	var logs bytes.Buffer
	h := newTestHandler(t, fakeDB{}, &logs)

	rec := do(h, http.MethodGet, "/healthz", nil, map[string]string{RequestIDHeader: "abc-123"})
	if got := rec.Header().Get(RequestIDHeader); got != "abc-123" {
		t.Errorf("valid request id not propagated: %q", got)
	}
	if !strings.Contains(logs.String(), `"request_id":"abc-123"`) {
		t.Errorf("request id missing from access log: %s", logs.String())
	}

	evil := "x\n{\"level\":\"ERROR\"}"
	rec = do(h, http.MethodGet, "/healthz", nil, map[string]string{RequestIDHeader: evil})
	got := rec.Header().Get(RequestIDHeader)
	if got == evil || !validRequestID.MatchString(got) {
		t.Errorf("unsafe request id accepted: %q", got)
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := do(newTestHandler(t, fakeDB{}, nil), http.MethodGet, "/healthz", nil, nil)
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Cache-Control"} {
		if rec.Header().Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	h := newTestHandler(t, fakeDB{}, nil)
	rec := do(h, http.MethodPost, "/api/v1/inventory/import", strings.NewReader(strings.Repeat("a", 2048)), nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body = %d, want 413", rec.Code)
	}
}

func TestRecoverHidesPanicDetails(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("db password is hunter2")
	}), RequestContext(log), Recover)

	rec := do(h, http.MethodGet, "/", nil, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Error("panic message leaked to client")
	}
	if !strings.Contains(logs.String(), "panic recovered") {
		t.Error("panic not logged")
	}
}
