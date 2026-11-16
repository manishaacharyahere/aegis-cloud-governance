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
	// An operator resets parked rows; they are then delivered.
	if _, err := pool.Exec(ctx, `UPDATE outbox_events SET attempts = 0`); err != nil {
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
	bus, err := natsbus.Connect(ctx, natsURL, "aegis-test")
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
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
