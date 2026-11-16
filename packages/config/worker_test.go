package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadWorkerDefaults(t *testing.T) {
	w, err := LoadWorker(env(map[string]string{"AEGIS_DATABASE_URL": "postgres://x"}))
	if err != nil {
		t.Fatal(err)
	}
	if w.Concurrency != 2 || w.Lease != 2*time.Minute || w.OPAURL != "http://127.0.0.1:8181" || w.ID == "" {
		t.Errorf("defaults: %+v", w)
	}
}

func TestLoadWorkerErrors(t *testing.T) {
	for _, tc := range []struct{ key, val, want string }{
		{"AEGIS_WORKER_CONCURRENCY", "0", "CONCURRENCY"},
		{"AEGIS_WORKER_CONCURRENCY", "x", "CONCURRENCY"},
		{"AEGIS_WORKER_LEASE", "1s", "AEGIS_WORKER_LEASE"},
		{"AEGIS_OPA_URL", "ftp://opa", "AEGIS_OPA_URL"},
		{"AEGIS_TOOL_TIMEOUT", "1h", "must not exceed"},
	} {
		_, err := LoadWorker(env(map[string]string{"AEGIS_DATABASE_URL": "x", tc.key: tc.val}))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s=%s: want %q, got %v", tc.key, tc.val, tc.want, err)
		}
	}
	if _, err := LoadWorker(env(nil)); err == nil || !strings.Contains(err.Error(), "AEGIS_DATABASE_URL") {
		t.Error("missing database URL not reported")
	}
}
