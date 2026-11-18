package integration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/natsbus"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/outbox"
)

type recordingPub struct {
	mu   sync.Mutex
	ids  map[string]int
	fail bool
}

func (p *recordingPub) Publish(_ context.Context, _, id string, _ []byte) error {
	if p.fail {
		return errors.New("broker unavailable")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ids[id]++
	return nil
}

func TestOutboxRelay(t *testing.T) {
	pool, _ := migratedPool(t)
	ctx := context.Background()
	seed := func(n int) {
		if _, err := pool.Exec(ctx, `INSERT INTO outbox_events (tenant_id, aggregate_type, aggregate_id, event_type, payload)
			SELECT (SELECT id FROM tenants WHERE slug = 'demo'), 'test', g::text, 'test.event', jsonb_build_object('n', g)
			FROM generate_series(1, $1) g`, n); err != nil {
			t.Fatal(err)
		}
	}

	// A broker outage: rows record the error and are parked after MaxAttempts.
	seed(5)
	down := &recordingPub{ids: map[string]int{}, fail: true}
	r := &outbox.Relay{Pool: pool, Pub: down, MaxAttempts: 2}
	for range 3 {
		if _, _, err := r.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM outbox_events WHERE attempts = 2 AND last_error = 'broker unavailable' AND published_at IS NULL`); n != 5 {
		t.Fatalf("failed rows recorded: %d of 5", n)
	}
	if pub, failed, _ := r.RunOnce(ctx); pub+failed != 0 {
		t.Fatal("parked rows were claimed again")
	}
	if n, err := r.Parked(ctx); err != nil || n != 5 {
		t.Fatalf("parked = %d %v", n, err)
	}
	// An admin requeues them; they are then delivered.
	if n, err := outbox.RequeueParked(ctx, pool, "demo", 2); err != nil || n != 5 {
		t.Fatalf("requeue = %d %v", n, err)
	}

	// A relay that died after claiming leaves its rows leased: nobody else
	// takes them until the lease expires, then another relay delivers them.
	if _, err := pool.Exec(ctx, `UPDATE outbox_events SET claimed_until = now() + interval '400 milliseconds', claimed_by = 'dead-relay'`); err != nil {
		t.Fatal(err)
	}
	other := &recordingPub{ids: map[string]int{}}
	if pub, _, err := (&outbox.Relay{Pool: pool, Pub: other}).RunOnce(ctx); err != nil || pub != 0 {
		t.Fatalf("leased rows were taken before the lease expired: %d %v", pub, err)
	}
	time.Sleep(500 * time.Millisecond)
	if pub, _, err := (&outbox.Relay{Pool: pool, Pub: other}).RunOnce(ctx); err != nil || pub != 5 {
		t.Fatalf("after lease expiry: %d %v", pub, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE outbox_events SET published_at = NULL, attempts = 0`); err != nil {
		t.Fatal(err)
	}

	// Two relays in parallel never publish the same row twice.
	seed(495)
	rec := &recordingPub{ids: map[string]int{}}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := &outbox.Relay{Pool: pool, Pub: rec, Batch: 37}
			for {
				pub, _, err := rr.RunOnce(ctx)
				if err != nil {
					t.Error(err)
					return
				}
				if pub == 0 {
					return
				}
			}
		}()
	}
	wg.Wait()
	if len(rec.ids) != 500 {
		t.Fatalf("published %d distinct events, want 500", len(rec.ids))
	}
	for id, n := range rec.ids {
		if n != 1 {
			t.Fatalf("event %s published %d times", id, n)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM outbox_events WHERE published_at IS NULL`); n != 0 {
		t.Fatalf("%d events left unpublished", n)
	}

	// Real JetStream: events arrive once, and a re-sent row is de-duplicated.
	natsURL := os.Getenv("AEGIS_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("AEGIS_TEST_NATS_URL not set; skipping the JetStream part")
	}
	bus, err := natsbus.Connect(ctx, natsURL, "aegis-test", natsbus.Credentials{
		User: os.Getenv("AEGIS_TEST_NATS_USER"), Password: os.Getenv("AEGIS_TEST_NATS_PASSWORD")})
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if os.Getenv("AEGIS_TEST_NATS_USER") != "" {
		// Anonymous clients are refused, and the Aegis user cannot publish outside aegis.>.
		if anon, err := natsbus.Connect(ctx, natsURL, "anonymous", natsbus.Credentials{}); err == nil {
			anon.Close()
			t.Error("anonymous NATS connection was accepted")
		}
		if err := bus.Publish(ctx, "evil.injected", "x1", []byte("{}")); err == nil {
			t.Error("publishing outside aegis.> was allowed")
		}
	}
	stream, err := bus.JetStream().Stream(ctx, natsbus.Stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Purge(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE outbox_events SET published_at = NULL, attempts = 0`); err != nil {
		t.Fatal(err)
	}
	real := &outbox.Relay{Pool: pool, Pub: bus, Batch: 200}
	for {
		pub, failed, err := real.RunOnce(ctx)
		if err != nil || failed > 0 {
			t.Fatalf("relay to NATS: %d failed, %v", failed, err)
		}
		if pub == 0 {
			break
		}
	}
	// Re-send ten rows as if the relay crashed before marking them published.
	if _, err := pool.Exec(ctx, `UPDATE outbox_events SET published_at = NULL WHERE id IN (SELECT id FROM outbox_events LIMIT 10)`); err != nil {
		t.Fatal(err)
	}
	if pub, _, err := real.RunOnce(ctx); err != nil || pub != 10 {
		t.Fatalf("re-send: %d %v", pub, err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 500 {
		t.Fatalf("stream holds %d messages, want 500 (duplicates must be dropped)", info.State.Msgs)
	}
	cons, err := stream.OrderedConsumer(ctx, jetstream.OrderedConsumerConfig{FilterSubjects: []string{"aegis.*.test.test_event"}})
	if err != nil {
		t.Fatal(err)
	}
	batch, err := cons.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for m := range batch.Messages() {
		var e outbox.Event
		if err := json.Unmarshal(m.Data(), &e); err != nil || e.Type != "test.event" || m.Headers().Get("Nats-Msg-Id") != e.ID {
			t.Fatalf("message: %+v %v", e, err)
		}
	}
}

type outageErr struct{}

func (outageErr) Error() string   { return "broker unavailable: no responders" }
func (outageErr) Transient() bool { return true }

type downPub struct{ calls int }

func (p *downPub) Publish(context.Context, string, string, []byte) error {
	p.calls++
	return outageErr{}
}

// A broker outage (transient errors) never parks events, however long it
// lasts, and the relay stops a batch at the first transient failure.
func TestOutboxOutageDoesNotPark(t *testing.T) {
	pool, _ := migratedPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO outbox_events (tenant_id, aggregate_type, aggregate_id, event_type, payload)
		SELECT (SELECT id FROM tenants WHERE slug = 'demo'), 'test', g::text, 'test.event', '{}' FROM generate_series(1, 5) g`); err != nil {
		t.Fatal(err)
	}
	down := &downPub{}
	r := &outbox.Relay{Pool: pool, Pub: down, MaxAttempts: 2}
	for range 10 {
		if _, _, err := r.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if down.calls != 10 {
		t.Errorf("publish calls = %d, want one per batch (stop at the first outage error)", down.calls)
	}
	if n, err := r.Parked(ctx); err != nil || n != 0 {
		t.Fatalf("outage parked %d events (%v)", n, err)
	}
	if n := count(t, pool, `SELECT count(*) FROM outbox_events WHERE attempts = 0 AND claimed_by IS NULL AND published_at IS NULL`); n != 5 {
		t.Fatalf("events not left ready for retry: %d of 5", n)
	}
	up := &recordingPub{ids: map[string]int{}}
	if pub, _, err := (&outbox.Relay{Pool: pool, Pub: up}).RunOnce(ctx); err != nil || pub != 5 {
		t.Fatalf("after the outage: %d %v", pub, err)
	}
}
