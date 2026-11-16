// Command aegis-worker executes background jobs (currently IaC scans).
//
// It runs on the host, not in a container, because it launches the
// sandboxed tool containers itself; mounting the Docker socket into a
// container would hand that container root on the host.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/config"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/database"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/telemetry"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/iac"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "aegis-worker:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.LoadWorker(os.LookupEnv)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	log := logging.New(os.Stdout, cfg.LogLevel, "aegis-worker")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tel, err := telemetry.Setup(ctx, "aegis-worker", "dev")
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tel.Shutdown(sctx)
	}()
	if addr := os.Getenv("AEGIS_WORKER_METRICS_ADDR"); addr != "" {
		go telemetry.ServeMetrics(ctx, addr, tel.MetricsHandler, log)
		log.Info("worker metrics", "addr", addr)
	}
	metrics, err := iac.NewMetrics(tel.Meter)
	if err != nil {
		return err
	}

	pool, err := database.OpenWith(ctx, cfg.DatabaseURL, database.Options{AppName: "aegis-worker"})
	if err != nil {
		return err
	}
	defer pool.Close()

	if _, err := os.Stat(cfg.FixturesDir); err != nil {
		return fmt.Errorf("fixtures directory: %w", err)
	}
	policy := &iac.OPAClient{BaseURL: cfg.OPAURL, Token: cfg.OPAToken, HTTP: &http.Client{Timeout: 30 * time.Second}}
	if b, err := policy.Bundle(ctx); err != nil {
		log.Warn("OPA not reachable yet; scans will retry", "error", err)
	} else {
		log.Info("policy bundle", "sha256", b.SHA256, "modules", len(b.Modules))
	}

	w := &iac.Worker{
		Queue: iac.NewStore(pool),
		Scanner: &iac.Pipeline{
			Tools: &iac.DockerRunner{
				Docker: cfg.Docker, Images: iac.DefaultImages,
				PluginVolume: cfg.PluginVolume, MirrorVolume: cfg.MirrorVolume, StepTimeout: cfg.StepTimeout,
			},
			Policy:      policy,
			FixturesDir: cfg.FixturesDir,
		},
		Log:          log,
		ID:           cfg.ID,
		Concurrency:  cfg.Concurrency,
		PollInterval: cfg.PollInterval,
		Lease:        cfg.Lease,
		JobTimeout:   cfg.JobTimeout,
		DrainTimeout: cfg.DrainTimeout,
		Metrics:      metrics,
	}
	return w.Run(ctx)
}
