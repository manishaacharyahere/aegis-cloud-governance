// Command aegis-api runs the Aegis control-plane HTTP API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manishaacharyahere/aegis-cloud-governance/migrations"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/config"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/database"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/logging"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/natsbus"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/opa"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/signing"
	"github.com/manishaacharyahere/aegis-cloud-governance/packages/telemetry"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/access"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/api"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/compliance"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/drift"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/finops"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/iac"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/investigator"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/outbox"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/remediation"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/retention"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/risk"
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

	tel, err := telemetry.Setup(ctx, "aegis-api", version)
	if err != nil {
		return fmt.Errorf("telemetry: %w", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tel.Shutdown(sctx)
	}()
	log.Info("telemetry", "traces_exported", tel.TracesExported, "metrics_addr", cfg.MetricsAddr)
	if cfg.MetricsAddr != "" {
		go serveMetrics(ctx, cfg.MetricsAddr, tel.MetricsHandler, log)
	}

	pool, err := database.OpenWith(ctx, cfg.DatabaseURL, database.Options{MaxConns: cfg.DBMaxConns,
		StatementTimeout: cfg.DBStatementTimeout, AppName: "aegis-api"})
	if err != nil {
		return err
	}
	defer pool.Close()
	// Background work (relay, retention) gets its own small pool so it can
	// never starve request handling, and a longer statement timeout.
	bg, err := database.OpenWith(ctx, cfg.DatabaseURL, database.Options{MaxConns: 4, StatementTimeout: 10 * time.Minute,
		AppName: "aegis-api-background"})
	if err != nil {
		return err
	}
	defer bg.Close()

	if cfg.MigrateOnStart {
		migs, err := database.LoadMigrations(migrations.FS)
		if err != nil {
			return err
		}
		// Migrations run as the schema owner when a separate URL is given; the
		// API itself then runs as the least-privilege aegis_app role.
		migPool := pool
		if cfg.MigrationDatabaseURL != "" {
			if migPool, err = database.OpenWith(ctx, cfg.MigrationDatabaseURL, database.Options{MaxConns: 2, AppName: "aegis-migrate"}); err != nil {
				return fmt.Errorf("migration database: %w", err)
			}
		}
		err = database.Migrate(ctx, migPool, migs, log)
		if migPool != pool {
			migPool.Close() // the owner connection is not kept for the API's lifetime
		}
		if err != nil {
			return err
		}
	}

	if cfg.BootstrapTenant != "" {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (slug, name) VALUES ($1, $1) ON CONFLICT (slug) DO NOTHING`,
			cfg.BootstrapTenant); err != nil {
			return fmt.Errorf("bootstrap tenant: %w", err)
		}
	}

	catalog, err := compliance.LoadCatalog()
	if err != nil {
		return err
	}
	log.Info("compliance catalog loaded", "version", catalog.Version, "sha256", catalog.SHA256)
	opaClient := &opa.Client{BaseURL: cfg.OPAURL, Token: cfg.OPAToken, HTTP: &http.Client{Timeout: 30 * time.Second}}

	ruleInfo := map[string]risk.RuleInfo{}
	counts := catalog.ControlCounts()
	for id, sev := range catalog.RuleSeverities() {
		ruleInfo[id] = risk.RuleInfo{Severity: sev, Controls: counts[id]}
	}

	ruleMeta := map[string]investigator.RuleMeta{}
	for _, id := range catalog.RuleIDs() {
		r, _ := catalog.Rule(id)
		ruleMeta[id] = investigator.RuleMeta{Title: r.Title, Severity: r.Severity, Remediation: r.Remediation}
	}
	inv := &investigator.Service{Pool: pool, Rules: ruleMeta, ModelTimeout: cfg.AI.Timeout}
	if cfg.AI.Provider == "ollama" {
		m, err := investigator.NewOllama(cfg.AI.URL, cfg.AI.Model, cfg.AI.Timeout, cfg.AI.AllowRemote)
		if err != nil {
			return fmt.Errorf("AI model: %w", err)
		}
		inv.Model = m
		inv.ModelSlots = make(chan struct{}, cfg.AI.MaxConcurrent)
		log.Info("investigation model enabled", "model", m.Name(), "remote_allowed", cfg.AI.AllowRemote)
	}

	signer := signing.Ephemeral()
	if cfg.SigningKey != "" {
		if signer, err = signing.FromSeed(cfg.SigningKey); err != nil {
			return fmt.Errorf("AEGIS_SIGNING_KEY: %w", err)
		}
	} else {
		log.Warn("AEGIS_SIGNING_KEY not set: using a throwaway signing key; signatures will not verify after a restart")
	}
	log.Info("signing key", "key_id", signer.KeyID)

	roles := &access.Store{Pool: pool}
	if len(cfg.BootstrapAdmins) > 0 {
		if err := roles.Bootstrap(ctx, cfg.BootstrapTenant, cfg.BootstrapAdmins); err != nil {
			return err
		}
	}
	auth := api.Auth{Mode: cfg.AuthMode, Roles: roles}
	if cfg.AuthMode == api.AuthOIDC {
		auth.Verifier = &access.Verifier{Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID}
		auth.Issuer, auth.ClientID = cfg.OIDCIssuer, cfg.OIDCClientID
		log.Info("authentication", "mode", "oidc", "issuer", cfg.OIDCIssuer, "client_id", cfg.OIDCClientID)
	} else {
		log.Warn("authentication is in dev-headers mode: X-Aegis-Actor is trusted and every caller has every permission; never expose this API")
	}

	srv := api.NewServer(cfg.HTTPAddr, api.NewHandler(api.Deps{
		Logger:     log,
		DB:         pool,
		Inventory:  inventory.NewService(inventory.NewStore(pool)),
		IaC:        iac.NewStore(pool),
		Compliance: &compliance.Service{Pool: pool, Catalog: catalog, OPA: opaClient},
		Catalog:    catalog,
		Drift: &drift.Service{Pool: pool, OPA: opaClient, Config: drift.DefaultConfig(),
			RuleSeverity: catalog.RuleSeverities()},
		Risk:         &risk.Service{Pool: pool, Rules: ruleInfo},
		FinOps:       &finops.Service{Pool: pool},
		Investigator: inv,
		Auth:         auth,
		OutboxRequeue: func(ctx context.Context, tenant string) (int64, error) {
			return outbox.RequeueParked(ctx, pool, tenant, 0)
		},
		RateLimit:   &api.RateLimit{PerMinute: cfg.RateLimitPerMinute, ExpensivePerMinute: cfg.RateLimitExpensivePerMinute},
		Remediation: &remediation.Service{Pool: pool, OPA: opaClient, Signer: signer},
		Signer:      signer,
		// Model timeout plus time to collect evidence and store the result.
		InvestigationWriteBudget: cfg.AI.Timeout + 15*time.Second,
		Version:                  version,
		MaxBodyBytes:             cfg.MaxBodyBytes,
		MaxImportBytes:           cfg.MaxImportBytes,
	}), log)

	if cfg.RetentionEvery > 0 {
		go retention.Run(ctx, bg, retention.DefaultPolicy(), cfg.RetentionEvery, log)
	}
	if cfg.NATSURL != "" {
		go runRelay(ctx, cfg.NATSURL, natsbus.Credentials{User: cfg.NATSUser, Password: cfg.NATSPassword}, bg, log, tel)
	} else {
		log.Warn("AEGIS_NATS_URL not set; outbox events are stored but not published")
	}

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

// runRelay connects to NATS (retrying until it is reachable) and publishes
// outbox events until ctx is cancelled.
func runRelay(ctx context.Context, url string, creds natsbus.Credentials, pool *pgxpool.Pool, log *slog.Logger, tel *telemetry.Telemetry) {
	wait := time.Second
	for {
		bus, err := natsbus.Connect(ctx, url, "aegis-api", creds)
		if err == nil {
			defer bus.Close()
			log.Info("outbox relay started", "stream", natsbus.Stream)
			r := &outbox.Relay{Pool: pool, Pub: bus, Log: log}
			if m, err := outbox.NewOTelMetrics(tel.Meter); err == nil {
				r.Metrics = m
			}
			_ = r.Run(ctx)
			return
		}
		log.Warn("NATS not reachable; outbox relay will retry", "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, 30*time.Second)
	}
}

// serveMetrics exposes Prometheus metrics on an internal address, separate
// from the public API port.
func serveMetrics(ctx context.Context, addr string, h http.Handler, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", h)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("metrics server stopped", "error", err)
	}
}
