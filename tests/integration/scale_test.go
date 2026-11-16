package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/api"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/drift"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/investigator"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/remediation"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/risk"
)

type latency struct {
	N   int     `json:"n"`
	P50 float64 `json:"p50_ms"`
	P95 float64 `json:"p95_ms"`
	Max float64 `json:"max_ms"`
}

func summarize(ds []time.Duration) latency {
	if len(ds) == 0 {
		return latency{}
	}
	slices.Sort(ds)
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	return latency{N: len(ds), P50: ms(ds[len(ds)/2]), P95: ms(ds[len(ds)*95/100]), Max: ms(ds[len(ds)-1])}
}

func timed(f func() error) (float64, error) {
	start := time.Now()
	err := f()
	return float64(time.Since(start).Microseconds()) / 1000, err
}

// httpLoad sends total GET requests from workers goroutines and returns the
// latency distribution and the number of non-200 responses.
func httpLoad(url string, workers, total int, hdr map[string]string) (latency, int, float64) {
	var mu sync.Mutex
	var ds []time.Duration
	failures := 0
	jobs := make(chan struct{}, total)
	for range total {
		jobs <- struct{}{}
	}
	close(jobs)
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: workers}}
	start := time.Now()
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				req, _ := http.NewRequest("GET", url, nil)
				for k, v := range hdr {
					req.Header.Set(k, v)
				}
				t0 := time.Now()
				resp, err := client.Do(req)
				d := time.Since(t0)
				ok := err == nil && resp.StatusCode == 200
				if resp != nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				mu.Lock()
				ds = append(ds, d)
				if !ok {
					failures++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	rps := float64(total) / time.Since(start).Seconds()
	return summarize(ds), failures, rps
}

// TestScale measures the whole pipeline at increasing inventory sizes.
//
//	AEGIS_SCALE_SIZES=100,1000,5000,10000 AEGIS_SCALE_OUT=benchmarks/scale.json go test ./tests/integration -run Scale -timeout 60m
func TestScale(t *testing.T) {
	sizesEnv, opaURL := os.Getenv("AEGIS_SCALE_SIZES"), os.Getenv("AEGIS_TEST_OPA_URL")
	if sizesEnv == "" || opaURL == "" {
		t.Skip("set AEGIS_SCALE_SIZES and AEGIS_TEST_OPA_URL to run the scale test")
	}
	cat, _ := compliance.LoadCatalog()
	meta := map[string]investigator.RuleMeta{}
	for _, id := range cat.RuleIDs() {
		r, _ := cat.Rule(id)
		meta[id] = investigator.RuleMeta{Title: r.Title, Severity: r.Severity, Remediation: r.Remediation}
	}
	rules := map[string]risk.RuleInfo{}
	counts := cat.ControlCounts()
	for id, sev := range cat.RuleSeverities() {
		rules[id] = risk.RuleInfo{Severity: sev, Controls: counts[id]}
	}
	oc := &opa.Client{BaseURL: opaURL, Token: os.Getenv("AEGIS_TEST_OPA_TOKEN"), HTTP: &http.Client{Timeout: 5 * time.Minute}}

	var results []map[string]any
	for _, sz := range strings.Split(sizesEnv, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(sz))
		if err != nil {
			t.Fatal(err)
		}
		pool, inv := migratedPool(t)
		ctx := context.Background()
		res := map[string]any{"target_resources": n}
		must := func(name string, f func() error) {
			ms, err := timed(f)
			if err != nil {
				t.Fatalf("n=%d %s: %v", n, name, err)
			}
			res[name+"_ms"] = ms
		}

		ds := synthetic.Generate(synthetic.Options{Seed: 42, Resources: n, CapturedAt: base})
		res["resources"] = len(ds.Snapshot.Resources)
		must("import", func() error { _, err := inv.Import(ctx, "demo", ds.Snapshot); return err })
		must("reimport_unchanged", func() error { _, err := inv.Import(ctx, "demo", ds.Snapshot); return err })

		dsvc := &drift.Service{Pool: pool, OPA: oc, Config: drift.DefaultConfig(), RuleSeverity: cat.RuleSeverities()}
		must("drift_baseline", func() error { _, err := dsvc.ApproveBaseline(ctx, "demo", "", "alice", "scale test"); return err })
		v2, _ := synthetic.Mutate(ds, synthetic.MutateOptions{Seed: 7, Modify: max(1, n/50), Delete: max(1, n/200), Add: max(1, n/200),
			CapturedAt: base.Add(time.Hour)})
		must("import_2pct_changed", func() error { _, err := inv.Import(ctx, "demo", v2.Snapshot); return err })
		must("drift_compare", func() error { _, err := dsvc.Compare(ctx, "demo", "", "alice"); return err })

		csvc := &compliance.Service{Pool: pool, Catalog: cat, OPA: oc}
		var sum compliance.RunSummary
		must("compliance_evaluate", func() error { var err error; sum, err = csvc.EvaluateInventory(ctx, "demo", "alice"); return err })
		res["findings"] = sum.Fail
		must("risk_assess", func() error {
			_, err := (&risk.Service{Pool: pool, Rules: rules}).Assess(ctx, "demo", "alice", risk.DefaultWeights())
			return err
		})

		// Investigations of 50 resources spread over the estate.
		isvc := &investigator.Service{Pool: pool, Rules: meta}
		rows, _ := pool.Query(ctx, `SELECT resource_id FROM resources WHERE deleted_at IS NULL ORDER BY md5(resource_id) LIMIT 50`)
		var ids []string
		for rows.Next() {
			var id string
			_ = rows.Scan(&id)
			ids = append(ids, id)
		}
		rows.Close()
		var invLat []time.Duration
		for _, id := range ids {
			t0 := time.Now()
			if _, err := isvc.Investigate(ctx, "demo", "alice", investigator.Request{ResourceID: id}); err != nil {
				t.Fatalf("investigate %s: %v", id, err)
			}
			invLat = append(invLat, time.Since(t0))
		}
		res["investigation"] = summarize(invLat)

		// Remediation proposals for up to 20 templated findings.
		templated := map[string]bool{}
		for _, tm := range remediation.Templates() {
			templated[tm.RuleID] = true
		}
		rsvc := &remediation.Service{Pool: pool, OPA: oc}
		var remLat []time.Duration
		for pair := range failingPairs(t, pool) {
			if len(remLat) == 20 {
				break
			}
			if !templated[pair[0]] {
				continue
			}
			t0 := time.Now()
			if _, err := rsvc.Propose(ctx, "demo", "alice", remediation.ProposeRequest{Source: "finding", RuleID: pair[0],
				ResourceID: pair[1], Justification: "scale test proposal"}); err != nil {
				t.Fatalf("propose: %v", err)
			}
			remLat = append(remLat, time.Since(t0))
		}
		res["remediation_propose"] = summarize(remLat)

		// API read path under concurrency (dev-headers auth, real services).
		h := api.NewHandler(api.Deps{Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)), DB: pool, Inventory: inv, MaxBodyBytes: 1 << 20})
		srv := httptest.NewServer(h)
		hdr := map[string]string{api.TenantHeader: "demo"}
		// Measured twice: right after the bulk writes above (autovacuum and
		// statistics still catching up), and after ANALYZE (settled).
		for _, phase := range []string{"after_bulk", "settled"} {
			if phase == "settled" {
				if _, err := pool.Exec(ctx, `ANALYZE`); err != nil {
					t.Fatal(err)
				}
			}
			for _, workers := range []int{1, 16} {
				lat, fails, rps := httpLoad(srv.URL+"/api/v1/resources?limit=100", workers, 400, hdr)
				if fails > 0 {
					t.Errorf("n=%d: %d failed list requests at concurrency %d", n, fails, workers)
				}
				res[fmt.Sprintf("api_list_c%d_%s", workers, phase)] = map[string]any{"latency": lat, "requests_per_second": int(rps)}
			}
		}
		srv.Close()

		var bytes int64
		_ = pool.QueryRow(ctx, `SELECT pg_total_relation_size('resources') + pg_total_relation_size('resource_versions')`).Scan(&bytes)
		res["inventory_tables_mb"] = float64(bytes/1024) / 1024
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		res["go_heap_inuse_mb"] = ms.HeapInuse / (1 << 20)
		t.Logf("n=%d: %v", n, res)
		results = append(results, res)
		pool.Close()
	}
	if out := os.Getenv("AEGIS_SCALE_OUT"); out != "" {
		raw, _ := json.MarshalIndent(map[string]any{
			"note":    "Single run on a developer laptop; PostgreSQL, OPA and the test process share the machine. Indicative, not a capacity guarantee.",
			"go":      runtime.Version(),
			"cpus":    runtime.NumCPU(),
			"results": results,
		}, "", "  ")
		if err := os.WriteFile(out, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
