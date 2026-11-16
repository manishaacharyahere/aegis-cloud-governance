package integration

import (
	"context"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/database"
)

// SQL statements appear as spans under the caller's span, without arguments.
func TestDatabaseSpans(t *testing.T) {
	if os.Getenv("AEGIS_TEST_DATABASE_URL") == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL not set")
	}
	rec := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	otel.SetTracerProvider(tp)
	defer otel.SetTracerProvider(prev)

	ctx := context.Background()
	pool, err := database.Open(ctx, os.Getenv("AEGIS_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx, parent := tp.Tracer("test").Start(ctx, "request")
	var n int
	if err := pool.QueryRow(ctx, `SELECT $1::int + 1`, 41).Scan(&n); err != nil || n != 42 {
		t.Fatalf("query: %d %v", n, err)
	}
	parent.End()
	found := false
	for _, s := range rec.Ended() {
		if s.Parent().SpanID() == parent.SpanContext().SpanID() && strings.Contains(s.Name(), "SELECT") {
			found = true
			for _, a := range s.Attributes() {
				if strings.Contains(a.Value.Emit(), "41") && string(a.Key) != "db.query.text" && string(a.Key) != "db.statement" {
					t.Errorf("query argument leaked into span attribute %s", a.Key)
				}
			}
		}
	}
	if !found {
		t.Errorf("no SQL span under the request span (got %d spans)", len(rec.Ended()))
	}
}
