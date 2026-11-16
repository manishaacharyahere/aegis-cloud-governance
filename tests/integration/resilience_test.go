package integration

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/database"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/api"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/remediation"
)

// faultProxy forwards TCP to target and can sever every connection, either
// immediately or after a number of client-to-server bytes.
type faultProxy struct {
	ln      net.Listener
	target  string
	down    atomic.Bool
	cutAt   atomic.Int64 // >0: cut once this many more client bytes have passed
	mu      sync.Mutex
	conns   map[net.Conn]bool
	cutDone chan struct{}
}

func newFaultProxy(t *testing.T, target string) *faultProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &faultProxy{ln: ln, target: target, conns: map[net.Conn]bool{}, cutDone: make(chan struct{}, 1)}
	go p.serve()
	t.Cleanup(func() { ln.Close(); p.cut() })
	return p
}

func (p *faultProxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		if p.down.Load() {
			c.Close()
			continue
		}
		s, err := net.Dial("tcp", p.target)
		if err != nil {
			c.Close()
			continue
		}
		p.mu.Lock()
		p.conns[c], p.conns[s] = true, true
		p.mu.Unlock()
		go p.pipe(s, c, true)
		go p.pipe(c, s, false)
	}
}

func (p *faultProxy) pipe(dst, src net.Conn, fromClient bool) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if fromClient {
				if left := p.cutAt.Load(); left > 0 && p.cutAt.Add(-int64(n)) <= 0 {
					p.cutAt.Store(0)
					p.cut()
					p.cutDone <- struct{}{}
					return
				}
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			dst.Close()
			return
		}
	}
}

// cut closes every connection and refuses new ones until restore.
func (p *faultProxy) cut() {
	p.down.Store(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.conns {
		c.Close()
	}
	p.conns = map[net.Conn]bool{}
}

func (p *faultProxy) restore() { p.down.Store(false) }

func readyz(h http.Handler) int {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	return rec.Code
}

func TestResilienceDatabaseLoss(t *testing.T) {
	direct, _ := migratedPool(t)
	ctx := context.Background()
	u, _ := url.Parse(os.Getenv("AEGIS_TEST_DATABASE_URL"))
	proxy := newFaultProxy(t, u.Host)
	pu := *u
	pu.Host = proxy.ln.Addr().String()
	pool, err := database.Open(ctx, pu.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	inv := inventory.NewService(inventory.NewStore(pool))
	h := api.NewHandler(api.Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: pool, MaxBodyBytes: 4096})

	if code := readyz(h); code != 200 {
		t.Fatalf("readyz before outage = %d", code)
	}

	// Sever the database connection part-way through writing a large import.
	ds := synthetic.Generate(synthetic.Options{Seed: 42, Resources: 3000, CapturedAt: base})
	proxy.cutAt.Store(256 << 10)
	_, err = inv.Import(ctx, "demo", ds.Snapshot)
	if err == nil {
		t.Fatal("import succeeded although the connection was cut mid-transaction")
	}
	t.Logf("import failed as expected: %v", err)
	select {
	case <-proxy.cutDone:
	default:
		t.Fatal("the cut was never triggered")
	}
	for _, q := range []string{"inventory_imports", "resources", "resource_versions", "outbox_events"} {
		if n := count(t, direct, "SELECT count(*) FROM "+q); n != 0 {
			t.Errorf("%s has %d rows after a failed import: the transaction was not atomic", q, n)
		}
	}
	if code := readyz(h); code != 503 {
		t.Errorf("readyz during outage = %d, want 503", code)
	}

	// The database comes back: readiness recovers and the same import succeeds.
	proxy.restore()
	deadline := time.Now().Add(10 * time.Second)
	for readyz(h) != 200 {
		if time.Now().After(deadline) {
			t.Fatal("readyz did not recover after the database returned")
		}
		time.Sleep(200 * time.Millisecond)
	}
	rep, err := inv.Import(ctx, "demo", ds.Snapshot)
	if err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	if n := count(t, direct, "SELECT count(*) FROM resources"); n != len(ds.Snapshot.Resources) || rep.Created != n {
		t.Errorf("after retry: %d resources, report %+v", n, rep.ImportSummary)
	}
}

// With the policy engine unreachable, decisions fail closed and nothing is stored.
func TestResiliencePolicyEngineDown(t *testing.T) {
	pool, inv := migratedPool(t)
	ctx := context.Background()
	ds := synthetic.Generate(synthetic.Options{Seed: 42, Resources: 200, CapturedAt: base})
	if _, err := inv.Import(ctx, "demo", ds.Snapshot); err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	deadURL := "http://" + ln.Addr().String()
	ln.Close() // nothing listens here any more
	dead := &opa.Client{BaseURL: deadURL, HTTP: &http.Client{Timeout: 2 * time.Second}}
	cat, _ := compliance.LoadCatalog()

	if _, err := (&compliance.Service{Pool: pool, Catalog: cat, OPA: dead}).EvaluateInventory(ctx, "demo", "alice"); err == nil {
		t.Fatal("compliance evaluation succeeded without a policy engine")
	}
	if n := count(t, pool, "SELECT count(*) FROM compliance_runs"); n != 0 {
		t.Errorf("%d compliance runs stored without a policy decision", n)
	}
	var bucket string
	for _, r := range ds.Snapshot.Resources {
		if r.ResourceType == "aws_s3_bucket" {
			bucket = r.ResourceID
			break
		}
	}
	if _, err := (&remediation.Service{Pool: pool, OPA: dead}).Propose(ctx, "demo", "alice", remediation.ProposeRequest{
		Source: "manual", ResourceID: bucket, Justification: "policy engine outage test",
		Operations: []remediation.Op{{Op: "set", Path: "configuration.versioning", Value: true}}}); err == nil {
		t.Fatal("remediation simulated without a policy engine")
	}
	if n := count(t, pool, "SELECT count(*) FROM remediations"); n != 0 {
		t.Errorf("%d remediations stored without a simulation", n)
	}
}
