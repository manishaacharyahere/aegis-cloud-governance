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

	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	bundle, err := iac.HashPolicies(cfg.PoliciesDir)
	if err != nil {
		return fmt.Errorf("hash policies in %s: %w", cfg.PoliciesDir, err)
	}
	if _, err := os.Stat(cfg.FixturesDir); err != nil {
		return fmt.Errorf("fixtures directory: %w", err)
	}
	log.Info("policy bundle", "sha256", bundle, "dir", cfg.PoliciesDir)

	w := &iac.Worker{
		Queue: iac.NewStore(pool),
		Scanner: &iac.Pipeline{
			Tools: &iac.DockerRunner{
				Docker: cfg.Docker, Images: iac.DefaultImages,
				PluginVolume: cfg.PluginVolume, StepTimeout: cfg.StepTimeout,
			},
			Policy:          &iac.OPAClient{BaseURL: cfg.OPAURL, HTTP: &http.Client{Timeout: 30 * time.Second}},
			FixturesDir:     cfg.FixturesDir,
			PolicyBundleSHA: bundle,
		},
		Log:          log,
		ID:           cfg.ID,
		Concurrency:  cfg.Concurrency,
		PollInterval: cfg.PollInterval,
		Lease:        cfg.Lease,
		JobTimeout:   cfg.JobTimeout,
		DrainTimeout: cfg.DrainTimeout,
	}
	return w.Run(ctx)
}
