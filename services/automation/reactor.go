package automation

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/natsbus"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/outbox"
)

// ImportSubject matches every tenant's completed inventory imports.
const ImportSubject = "aegis.*.inventory_import.inventory_import_completed"

// reactorAckWait bounds how long an import event may wait for its debounced
// evaluation before JetStream redelivers it. Evaluations of large estates
// take tens of seconds, so this is generous; a redelivery only re-arms the
// debounce timer.
const reactorAckWait = 5 * time.Minute

// RunReactor re-evaluates a tenant shortly after each completed inventory
// import, so compliance and risk are never older than the latest inventory.
// Imports arriving within debounce of each other cause one evaluation.
//
// Messages are acknowledged only after that evaluation succeeded. If it
// fails (OPA down, database error) they are negatively acknowledged with a
// delay, so JetStream delivers them again (up to MaxDeliver). If the process
// stops first, they are redelivered after the ack wait: an import never
// silently loses its evaluation.
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
		DeliverPolicy: jetstream.DeliverNewPolicy, MaxDeliver: 5, AckWait: reactorAckWait,
	})
	if err != nil {
		return err
	}
	var mu sync.Mutex
	type pending struct {
		timer *time.Timer
		msgs  []jetstream.Msg
	}
	waiting := map[string]*pending{}
	var inflight sync.WaitGroup

	evaluate := func(tenantID string) {
		defer inflight.Done()
		mu.Lock()
		p := waiting[tenantID]
		delete(waiting, tenantID)
		mu.Unlock()
		if p == nil {
			return
		}
		settle := func(ok bool) {
			for _, m := range p.msgs {
				if ok {
					_ = m.Ack()
				} else {
					_ = m.NakWithDelay(30 * time.Second)
				}
			}
		}
		var slug string
		if err := a.Pool.QueryRow(ctx, `SELECT slug FROM tenants WHERE id = $1`, tenantID).Scan(&slug); err != nil {
			a.log().Warn("reactor: unknown tenant", "tenant_id", tenantID, "error", err)
			// Only a deleted tenant will never succeed; a database error is retried.
			settle(errors.Is(err, pgx.ErrNoRows))
			return
		}
		if err := a.Evaluate(ctx, slug); err != nil {
			if ctx.Err() == nil {
				a.log().Warn("reactor: evaluation after import failed; will retry", "tenant", slug, "error", err)
			}
			settle(false)
			return
		}
		settle(true)
		a.log().Info("reactor: re-evaluated after import", "tenant", slug, "events", len(p.msgs))
	}

	schedule := func(tenantID string, m jetstream.Msg) {
		mu.Lock()
		defer mu.Unlock()
		if p, ok := waiting[tenantID]; ok {
			p.msgs = append(p.msgs, m)
			if p.timer.Stop() {
				p.timer.Reset(debounce)
			}
			return
		}
		inflight.Add(1)
		waiting[tenantID] = &pending{msgs: []jetstream.Msg{m}, timer: time.AfterFunc(debounce, func() { evaluate(tenantID) })}
	}
	cc, err := cons.Consume(func(m jetstream.Msg) {
		var e outbox.Event
		if err := json.Unmarshal(m.Data(), &e); err != nil || e.TenantID == "" {
			_ = m.Term() // malformed: never redeliver
			return
		}
		schedule(e.TenantID, m)
	})
	if err != nil {
		return err
	}
	<-ctx.Done()
	cc.Stop()
	mu.Lock()
	for _, p := range waiting {
		if p.timer.Stop() {
			inflight.Done() // never fired; its messages are redelivered after the ack wait
		}
	}
	mu.Unlock()
	inflight.Wait()
	return nil
}
