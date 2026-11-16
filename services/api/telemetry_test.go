package api

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/telemetry"
)

func TestTelemetry(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	defer otel.SetTracerProvider(prev)
	tel, err := telemetry.Setup(context.Background(), "aegis-api-test", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()

	var logs bytes.Buffer
	h := NewHandler(Deps{Logger: slog.New(slog.NewJSONHandler(&logs, nil)), DB: fakeDB{}, MaxBodyBytes: 4096,
		Investigator: &fakeInvestigator{}})
	do(h, "GET", "/api/v1/investigations/0b5c3a52-5f7a-4a55-9b38-2e1f0c4f8a11", nil, tenantHdr)
	do(h, "GET", "/api/v1/version", nil, nil)
	evil := httptest.NewRequest("GET", "/api/v1/version", nil)
	evil.Host = "attacker-chosen-host.example"
	h.ServeHTTP(httptest.NewRecorder(), evil)

	names := map[string]bool{}
	for _, s := range rec.Ended() {
		names[s.Name()] = true
	}
	if !names["GET /api/v1/investigations/{id}"] || !names["GET /api/v1/version"] {
		t.Errorf("span names should be route patterns, got %v", names)
	}
	if !strings.Contains(logs.String(), `"trace_id":"`) {
		t.Error("request logs must carry the trace ID")
	}

	mrec := httptest.NewRecorder()
	tel.MetricsHandler.ServeHTTP(mrec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(mrec.Body)
	m := string(body)
	if !strings.Contains(m, "http_server_request_duration_seconds") || !strings.Contains(m, `http_route="/api/v1/investigations/{id}"`) {
		t.Errorf("request duration metric with route label missing:\n%.2000s", m)
	}
	if strings.Contains(m, "attacker-chosen-host") {
		t.Error("the client-controlled Host header must not become a metric label")
	}
	if strings.Contains(m, "0b5c3a52") {
		t.Error("resource IDs must not appear in metric labels")
	}
}
