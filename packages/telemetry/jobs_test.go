package telemetry

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestJobRecordsOutcomesAndLastSuccess(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	job := NewJob("retention")
	job.Observe(time.Now(), nil)
	job.Observe(time.Now(), errors.New("database down"))

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	runs := map[string]int64{}
	lastOK := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch m.Name {
			case "aegis.job.runs":
				for _, p := range m.Data.(metricdata.Sum[int64]).DataPoints {
					o, _ := p.Attributes.Value("outcome")
					runs[o.AsString()] += p.Value
				}
			case "aegis.job.last_success":
				for _, p := range m.Data.(metricdata.Gauge[float64]).DataPoints {
					j, _ := p.Attributes.Value("job")
					lastOK = j.AsString() == "retention" && p.Value > 1e9
				}
			}
		}
	}
	if runs["success"] != 1 || runs["failure"] != 1 {
		t.Errorf("runs by outcome = %v", runs)
	}
	if !lastOK {
		t.Error("last_success was not recorded for the successful run")
	}
}
