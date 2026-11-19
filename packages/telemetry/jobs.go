package telemetry

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Job instruments one kind of background work (retention, the scheduled
// evaluation, the import reactor). Three series per job, the usual set for
// alerting on jobs that fail quietly:
//
//	aegis.job.runs{job, outcome}       runs by outcome (success, failure)
//	aegis.job.duration{job}            seconds per run
//	aegis.job.last_success{job}        unix time of the last success; alert
//	                                   when now - last_success grows too large
//
// The instruments use the global meter provider, so they are no-ops until
// telemetry.Setup installs one (tests need no wiring).
type Job struct {
	name string
	attr metric.MeasurementOption
}

var (
	jobOnce     sync.Once
	jobRuns     metric.Int64Counter
	jobDuration metric.Float64Histogram
	jobLastOK   metric.Float64Gauge
)

// NewJob returns the recorder for the named job.
func NewJob(name string) *Job {
	jobOnce.Do(func() {
		m := otel.GetMeterProvider().Meter("aegis/jobs")
		jobRuns, _ = m.Int64Counter("aegis.job.runs", metric.WithDescription("Background job runs by outcome"))
		jobDuration, _ = m.Float64Histogram("aegis.job.duration", metric.WithUnit("s"), metric.WithDescription("Background job run time"))
		jobLastOK, _ = m.Float64Gauge("aegis.job.last_success", metric.WithUnit("s"),
			metric.WithDescription("Unix time of the job's last successful run"))
	})
	return &Job{name: name, attr: metric.WithAttributes(attribute.String("job", name))}
}

// Observe records one run that started at start and ended with err.
func (j *Job) Observe(start time.Time, err error) {
	ctx := context.Background()
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	if jobRuns != nil {
		jobRuns.Add(ctx, 1, metric.WithAttributes(attribute.String("job", j.name), attribute.String("outcome", outcome)))
	}
	if jobDuration != nil {
		jobDuration.Record(ctx, time.Since(start).Seconds(), j.attr)
	}
	if err == nil && jobLastOK != nil {
		jobLastOK.Record(ctx, float64(time.Now().Unix()), j.attr)
	}
}
