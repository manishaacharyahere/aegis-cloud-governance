package automation

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/natsbus"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/outbox"
)

// ImportSubject matches every tenant's completed inventory imports.
const ImportSubject = "aegis.*.inventory_import.inventory_import_completed"

// RunReactor re-evaluates a tenant shortly after each completed inventory
// import, so compliance and risk are never older than the latest inventory.
// Imports arriving within Debounce of each other cause one evaluation.
// Messages are acknowledged after the tenant is scheduled; the durable
// consumer resumes where it stopped after a restart.
func (a *Automation) RunReactor(ctx context.Context, js jetstream.JetStream, debounce time.Duration) error {
	if debounce <= 0 {
		debounce = 10 * time.Second
	}
	durable := a.Consumer
	if durable == "" {
		durable = "aegis-reactor"
	}
	cons, err := js.CreateOrUpdateConsumer(ctx, natsbus.Stream, jetstream.ConsumerConfig{
		Durable: durable, FilterSubject: ImportSubject, AckPolicy: jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverNewPolicy, MaxDeliver: 5, AckWait: 30 * time.Second,
	})
	if err != nil {
		return err
	}
	var mu sync.Mutex
	timers := map[string]*time.Timer{}
	schedule := func(tenantID string) {
		mu.Lock()
		defer mu.Unlock()
		if t, ok := timers[tenantID]; ok {
			t.Reset(debounce)
			return
		}
		timers[tenantID] = time.AfterFunc(debounce, func() {
			mu.Lock()
			delete(timers, tenantID)
			mu.Unlock()
			var slug string
			if err := a.Pool.QueryRow(ctx, `SELECT slug FROM tenants WHERE id = $1`, tenantID).Scan(&slug); err != nil {
				a.log().Warn("reactor: unknown tenant", "tenant_id", tenantID, "error", err)
				return
			}
			if err := a.Evaluate(ctx, slug); err != nil && ctx.Err() == nil {
				a.log().Warn("reactor: evaluation after import failed", "tenant", slug, "error", err)
				return
			}
			a.log().Info("reactor: re-evaluated after import", "tenant", slug)
		})
	}
	cc, err := cons.Consume(func(m jetstream.Msg) {
		var e outbox.Event
		if err := json.Unmarshal(m.Data(), &e); err != nil || e.TenantID == "" {
			_ = m.Term() // malformed: never redeliver
			return
		}
		schedule(e.TenantID)
		_ = m.Ack()
	})
	if err != nil {
		return err
	}
	<-ctx.Done()
	cc.Stop()
	mu.Lock()
	for _, t := range timers {
		t.Stop()
	}
	mu.Unlock()
	return nil
}
