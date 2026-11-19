package iac

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// RegisterQueueMetrics reports the scan queue on every metrics scrape:
//
//	aegis.iac.queue.depth{status}    scans queued and running
//	aegis.iac.queue.oldest_queued    seconds the oldest queued scan has waited
//
// A growing oldest_queued is the signal that no worker is taking scans.
func RegisterQueueMetrics(m metric.Meter, pool *pgxpool.Pool) error {
	depth, err := m.Int64ObservableGauge("aegis.iac.queue.depth", metric.WithDescription("IaC scans queued and running"))
	if err != nil {
		return err
	}
	oldest, err := m.Float64ObservableGauge("aegis.iac.queue.oldest_queued", metric.WithUnit("s"),
		metric.WithDescription("Seconds the oldest queued IaC scan has waited"))
	if err != nil {
		return err
	}
	_, err = m.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		var queued, running int64
		var wait float64
		if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'queued'), count(*) FILTER (WHERE status = 'running'),
			coalesce(extract(epoch FROM now() - min(created_at) FILTER (WHERE status = 'queued')), 0)::float8
			FROM iac_scans WHERE status IN ('queued', 'running')`).Scan(&queued, &running, &wait); err != nil {
			return err // this scrape reports nothing rather than a wrong zero
		}
		o.ObserveInt64(depth, queued, metric.WithAttributes(attribute.String("status", "queued")))
		o.ObserveInt64(depth, running, metric.WithAttributes(attribute.String("status", "running")))
		o.ObserveFloat64(oldest, wait)
		return nil
	}, depth, oldest)
	return err
}
