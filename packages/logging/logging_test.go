package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestNewWritesJSONWithService(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, slog.LevelInfo, "aegis-api").Info("hello", "k", "v")

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v (%q)", err, buf.String())
	}
	if rec["service"] != "aegis-api" || rec["msg"] != "hello" || rec["k"] != "v" {
		t.Errorf("unexpected record: %v", rec)
	}
}

func TestLevelFilters(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, slog.LevelWarn, "x").Info("dropped")
	if buf.Len() != 0 {
		t.Errorf("info should be filtered at warn level, got %q", buf.String())
	}
}

func TestContextRoundTrip(t *testing.T) {
	l := New(&bytes.Buffer{}, slog.LevelInfo, "x")
	if FromContext(WithLogger(context.Background(), l)) != l {
		t.Error("logger not recovered from context")
	}
	if FromContext(context.Background()) != slog.Default() {
		t.Error("empty context should yield default logger")
	}
}
