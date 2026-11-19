package integration

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/natsbus"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/automation"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/drift"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/outbox"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/remediation"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/risk"
)

type recordingNotifier struct {
	mu   sync.Mutex
	msgs []string
	down bool // the webhook is failing
}

func (r *recordingNotifier) Notify(_ context.Context, text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.down {
		return errors.New("webhook unavailable")
	}
	r.msgs = append(r.msgs, text)
	return nil
}

func (r *recordingNotifier) setDown(v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.down = v
}

func (r *recordingNotifier) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.msgs...)
}

func newAutomation(t *testing.T, opaURL string) (*automation.Automation, *recordingNotifier) {
	t.Helper()
	pool, _ := migratedPool(t)
	cat, _ := compliance.LoadCatalog()
	rules := map[string]risk.RuleInfo{}
	for id, sev := range cat.RuleSeverities() {
		rules[id] = risk.RuleInfo{Severity: sev, Controls: 1}
	}
	n := &recordingNotifier{}
	return &automation.Automation{Pool: pool,
		Compliance: &compliance.Service{Pool: pool, Catalog: cat, OPA: testOPA(opaURL)},
		Risk:       &risk.Service{Pool: pool, Rules: rules},
		Drift:      &drift.Service{Pool: pool, OPA: testOPA(opaURL), Config: drift.DefaultConfig(), RuleSeverity: cat.RuleSeverities()},
		Notify:     n}, n
}

func TestAutomationEvaluateAndRemind(t *testing.T) {
	opaURL := os.Getenv("AEGIS_TEST_OPA_URL")
	if opaURL == "" {
		t.Skip("AEGIS_TEST_OPA_URL not set")
	}
	a, n := newAutomation(t, opaURL)
	ctx := context.Background()
	pool := a.Pool

	// No inventory yet: nothing to do, no error.
	if err := a.Evaluate(ctx, "demo"); err != nil {
		t.Fatalf("empty tenant: %v", err)
	}
	inv := inventoryFor(pool)
	ds := synthetic.Generate(synthetic.Options{Seed: 42, Resources: 300, CapturedAt: base})
	if _, err := inv.Import(ctx, "demo", "tester", ds.Snapshot); err != nil {
		t.Fatal(err)
	}
	// The reactor and the scheduler can evaluate at the same moment: the
	// evaluations are serialised, so the risk increase is reported once.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = a.Evaluate(ctx, "demo")
		}()
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Fatal(err)
	}
	if c := count(t, pool, `SELECT count(*) FROM compliance_runs WHERE actor = $1`, automation.Actor); c != 2 {
		t.Errorf("automated compliance runs = %d", c)
	}
	if c := count(t, pool, `SELECT count(*) FROM risk_runs WHERE actor = $1`, automation.Actor); c != 2 {
		t.Errorf("automated risk runs = %d", c)
	}
	if msgs := n.all(); len(msgs) != 1 || !strings.Contains(msgs[0], "critical and high risks rose from 0") {
		t.Fatalf("risk alert: %v", msgs)
	}
	// Same estate again: no new alert.
	if err := a.Evaluate(ctx, "demo"); err != nil || len(n.all()) != 1 {
		t.Errorf("unchanged risk must not alert again: %v %v", n.all(), err)
	}

	// Reminders: an old pending remediation and an exception about to expire.
	rsvc := &remediation.Service{Pool: pool, OPA: testOPA(opaURL)}
	rem, err := rsvc.Propose(ctx, "demo", "alice", remediation.ProposeRequest{Source: "manual", ResourceID: ds.Snapshot.Resources[0].ResourceID,
		Justification: "reminder test change", Operations: []remediation.Op{{Op: "set", Path: "tags.reminder", Value: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE remediations SET created_at = now() - interval '2 days' WHERE id = $1`, rem.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO policy_exceptions (tenant_id, rule_id, subject, justification, status, requested_by, decided_by, created_at, expires_at)
		SELECT id, 'AEGIS-S3-002', 'aws_s3_bucket.x', 'temporary exception for the reminder test', 'approved', 'alice', 'bob', now() - interval '20 days', now() + interval '3 days'
		FROM tenants WHERE slug = 'demo'`); err != nil {
		t.Fatal(err)
	}
	// A failing webhook must not mark the reminders as sent.
	n.setDown(true)
	if sent, err := a.Remind(ctx, "demo"); err == nil || sent != 0 {
		t.Fatalf("reminders with the webhook down: sent %d, %v", sent, err)
	}
	n.setDown(false)
	sent, err := a.Remind(ctx, "demo")
	if err != nil || sent != 2 {
		t.Fatalf("reminders sent = %d, %v (%v)", sent, err, n.all())
	}
	if sent, _ := a.Remind(ctx, "demo"); sent != 0 {
		t.Errorf("reminders must not repeat within a day, sent %d", sent)
	}
}

// An import event published through the outbox reaches the reactor, which
// re-evaluates the tenant without anyone calling the API.
func TestAutomationReactor(t *testing.T) {
	opaURL, natsURL := os.Getenv("AEGIS_TEST_OPA_URL"), os.Getenv("AEGIS_TEST_NATS_URL")
	if opaURL == "" || natsURL == "" {
		t.Skip("AEGIS_TEST_OPA_URL and AEGIS_TEST_NATS_URL not set")
	}
	a, _ := newAutomation(t, opaURL)
	// Own consumer: a locally running API shares the default one and would
	// take the event.
	a.Consumer = "aegis-reactor-test"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus, err := natsbus.Connect(ctx, natsURL, "aegis-test-reactor", natsbus.Credentials{
		User: os.Getenv("AEGIS_TEST_NATS_USER"), Password: os.Getenv("AEGIS_TEST_NATS_PASSWORD")})
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	go func() { _ = a.RunReactor(ctx, bus.JetStream(), 200*time.Millisecond) }()
	// The consumer delivers events published after it was created: wait until
	// it exists (a fixed sleep was flaky on a slow runner).
	ready := time.Now().Add(10 * time.Second)
	for {
		if _, err := bus.JetStream().Consumer(ctx, natsbus.Stream, a.Consumer); err == nil {
			break
		}
		if time.Now().After(ready) {
			t.Fatal("reactor consumer was not created")
		}
		time.Sleep(50 * time.Millisecond)
	}

	ds := synthetic.Generate(synthetic.Options{Seed: 7, Resources: 200, CapturedAt: base})
	if _, err := inventoryFor(a.Pool).Import(ctx, "demo", "tester", ds.Snapshot); err != nil {
		t.Fatal(err)
	}
	relay := &outbox.Relay{Pool: a.Pool, Pub: bus}
	for {
		pub, _, err := relay.RunOnce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if pub == 0 {
			break
		}
	}
	deadline := time.Now().Add(20 * time.Second)
	for count(t, a.Pool, `SELECT count(*) FROM compliance_runs WHERE actor = $1`, automation.Actor) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the import event did not trigger an evaluation")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func inventoryFor(pool *pgxpool.Pool) *inventory.Service {
	return inventory.NewService(inventory.NewStore(pool))
}
