// Command aegis-api runs the Aegis control-plane HTTP API.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/manishaacharyahere/aegis-cloud-governance/migrations"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/config"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/database"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/api"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/iac"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "aegis-api:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	log := logging.New(os.Stdout, cfg.LogLevel, "aegis-api")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	if cfg.MigrateOnStart {
		migs, err := database.LoadMigrations(migrations.FS)
		if err != nil {
			return err
		}
		if err := database.Migrate(ctx, pool, migs, log); err != nil {
			return err
		}
	}

	if cfg.BootstrapTenant != "" {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (slug, name) VALUES ($1, $1) ON CONFLICT (slug) DO NOTHING`,
			cfg.BootstrapTenant); err != nil {
			return fmt.Errorf("bootstrap tenant: %w", err)
		}
	}

	srv := api.NewServer(cfg.HTTPAddr, api.NewHandler(api.Deps{
		Logger:         log,
		DB:             pool,
		Inventory:      inventory.NewService(inventory.NewStore(pool)),
		IaC:            iac.NewStore(pool),
		Version:        version,
		MaxBodyBytes:   cfg.MaxBodyBytes,
		MaxImportBytes: cfg.MaxImportBytes,
	}), log)

	errCh := make(chan error, 1)
	go func() {
		log.Info("api listening", "addr", cfg.HTTPAddr, "env", cfg.Environment, "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	// Graceful shutdown: stop accepting connections, drain in-flight requests.
	log.Info("shutting down", "timeout", cfg.ShutdownTimeout)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Info("shutdown complete")
	return nil
}
