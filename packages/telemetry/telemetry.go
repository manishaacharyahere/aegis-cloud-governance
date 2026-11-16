// Package telemetry sets up OpenTelemetry for Aegis processes: traces are
// exported over OTLP/HTTP when the standard OTEL_EXPORTER_OTLP_* variables
// are set, and metrics are exposed in Prometheus format on a handler that
// the caller serves on an internal port.
package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
)

// Telemetry holds the configured providers.
type Telemetry struct {
	Meter          metric.Meter
	MetricsHandler http.Handler
	TracesExported bool
	shutdown       []func(context.Context) error
}

// TracingConfigured reports whether an OTLP endpoint is set in the environment.
func TracingConfigured(lookup func(string) (string, bool)) bool {
	for _, k := range []string{"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"} {
		if v, ok := lookup(k); ok && v != "" {
			return true
		}
	}
	return false
}

// Setup installs global tracer and meter providers for service.
func Setup(ctx context.Context, service, version string) (*Telemetry, error) {
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName(service), semconv.ServiceVersion(version)))
	if err != nil {
		return nil, err
	}
	t := &Telemetry{}
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	if TracingConfigured(os.LookupEnv) {
		exp, err := otlptracehttp.New(ctx) // endpoint, headers and TLS from OTEL_EXPORTER_OTLP_* variables
		if err != nil {
			return nil, err
		}
		tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res),
			sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())))
		otel.SetTracerProvider(tp)
		t.TracesExported = true
		t.shutdown = append(t.shutdown, tp.Shutdown)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	exp, err := otelprom.New(otelprom.WithRegisterer(reg))
	if err != nil {
		return nil, err
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exp), sdkmetric.WithResource(res))
	otel.SetMeterProvider(mp)
	t.shutdown = append(t.shutdown, mp.Shutdown)
	t.Meter = mp.Meter("github.com/manishaacharyahere/aegis-cloud-governance")
	t.MetricsHandler = promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	return t, nil
}

// ServeMetrics exposes Prometheus metrics on an internal address (separate
// from any public port) until ctx is cancelled.
func ServeMetrics(ctx context.Context, addr string, h http.Handler, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", h)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("metrics server stopped", "error", err)
	}
}

// Shutdown flushes and stops the providers.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	var errs []error
	for _, f := range t.shutdown {
		errs = append(errs, f(ctx))
	}
	return errors.Join(errs...)
}
