// Command aegis-collect reads an AWS account (read-only) and writes an
// aegis.inventory/v1 snapshot, or imports it into Aegis directly.
//
//	aws configure --profile aegis-readonly        # a user or role with SecurityAudit
//	go run ./cmd/aegis-collect -profile aegis-readonly -regions ap-south-1,us-east-1 -out snapshot.json
//	go run ./cmd/aegis-collect -profile aegis-readonly -import http://127.0.0.1:8080 -tenant demo
//
// With -import, the bearer token is read from AEGIS_TOKEN (never a flag, so it
// stays out of shell history); without a token the development actor header
// is sent instead.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/collector"
	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "aegis-collect:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("aegis-collect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "", "AWS shared-config profile (default: the standard credential chain)")
	regions := fs.String("regions", "", `comma-separated regions, or "all" (default: the profile's region)`)
	endpoint := fs.String("endpoint", "", "custom AWS endpoint, for an emulator such as moto (testing only)")
	name := fs.String("account-name", "", "display name of the account (default aws-<id>)")
	env := fs.String("environment", "", "environment for resources without an environment tag")
	out := fs.String("out", "", "write the snapshot to this file (default: stdout)")
	api := fs.String("import", "", "import into this Aegis API instead of writing a file, e.g. http://127.0.0.1:8080")
	tenant := fs.String("tenant", "demo", "tenant to import into (with -import)")
	actor := fs.String("actor", "", "development actor header (with -import and no AEGIS_TOKEN)")
	timeout := fs.Duration("timeout", 10*time.Minute, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	var rs []string
	for _, r := range strings.Split(*regions, ",") {
		if r = strings.TrimSpace(r); r != "" {
			rs = append(rs, r)
		}
	}
	c, err := collector.New(ctx, collector.Options{Profile: *profile, Regions: rs, Endpoint: *endpoint, AccountName: *name, Environment: *env})
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "collecting account %s in %s\n", c.AccountID, strings.Join(c.Regions, ", "))
	snap, warnings, err := c.Collect(ctx)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintln(stderr, "warning:", w)
	}
	// Fail here, with every problem listed, rather than at the API.
	if err := inventory.Validate(snap, time.Now()); err != nil {
		return fmt.Errorf("the collected snapshot is invalid: %w", err)
	}
	fmt.Fprintf(stderr, "%d resources collected (%d warnings)\n", len(snap.Resources), len(warnings))

	raw, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	if *api != "" {
		return post(ctx, *api, *tenant, *actor, raw, stdout)
	}
	if *out == "" {
		_, err = stdout.Write(append(raw, '\n'))
		return err
	}
	return os.WriteFile(*out, append(raw, '\n'), 0o600)
}

func post(ctx context.Context, base, tenant, actor string, body []byte, stdout io.Writer) error {
	u, err := url.JoinPath(base, "/api/v1/inventory/import")
	if err != nil {
		return fmt.Errorf("-import: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Aegis-Tenant", tenant)
	if tok := os.Getenv("AEGIS_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	} else if actor != "" {
		req.Header.Set("X-Aegis-Actor", actor)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return fmt.Errorf("import failed: %s: %s", res.Status, bytes.TrimSpace(answer))
	}
	_, err = stdout.Write(append(answer, '\n'))
	return err
}
