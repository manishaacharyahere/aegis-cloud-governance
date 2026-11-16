// Command aegis-datagen writes a reproducible synthetic inventory dataset:
// a baseline snapshot, a drifted follow-up snapshot, ground-truth labels and
// a manifest recording everything needed to regenerate it.
//
//	go run ./cmd/aegis-datagen -seed 42 -resources 1000 -out datasets/inventory/generated
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/manishaacharyahere/aegis-cloud-governance/services/inventory/synthetic"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "aegis-datagen:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("aegis-datagen", flag.ContinueOnError)
	seed := fs.Uint64("seed", 42, "random seed")
	resources := fs.Int("resources", 1000, "approximate number of resources")
	modify := fs.Int("modify", 25, "resources to modify in the drifted snapshot")
	del := fs.Int("delete", 10, "resources to delete in the drifted snapshot")
	add := fs.Int("add", 15, "unmanaged resources to add in the drifted snapshot")
	out := fs.String("out", "datasets/inventory/generated", "output directory")
	captured := fs.String("captured-at", "2026-01-01T00:00:00Z", "baseline capture time (RFC 3339)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *resources < 1 || *resources > 100_000 {
		return fmt.Errorf("-resources must be between 1 and 100000")
	}
	t0, err := time.Parse(time.RFC3339, *captured)
	if err != nil {
		return fmt.Errorf("-captured-at: %w", err)
	}

	base := synthetic.Generate(synthetic.Options{Seed: *seed, Resources: *resources, CapturedAt: t0})
	next, mutation := synthetic.Mutate(base, synthetic.MutateOptions{
		Seed: *seed + 1, Modify: *modify, Delete: *del, Add: *add, CapturedAt: t0.Add(24 * time.Hour),
	})

	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	files := map[string]any{
		"snapshot-v1.json": base.Snapshot,
		"snapshot-v2.json": next.Snapshot,
		"labels-v1.json":   base.Labels,
		"labels-v2.json":   next.Labels,
		"mutation.json":    mutation,
	}
	hashes := map[string]string{}
	for _, name := range []string{"snapshot-v1.json", "snapshot-v2.json", "labels-v1.json", "labels-v2.json", "mutation.json"} {
		b, err := json.MarshalIndent(files[name], "", "  ")
		if err != nil {
			return err
		}
		b = append(b, '\n')
		if err := os.WriteFile(filepath.Join(*out, name), b, 0o644); err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		hashes[name] = hex.EncodeToString(sum[:])
	}

	manifest := map[string]any{
		"dataset":           "aegis-synthetic-inventory",
		"generator_version": synthetic.GeneratorVersion,
		"seed":              *seed,
		"parameters": map[string]any{
			"resources": *resources, "modify": *modify, "delete": *del, "add": *add, "captured_at": t0.Format(time.RFC3339),
		},
		"counts": map[string]int{
			"v1_resources": len(base.Snapshot.Resources), "v2_resources": len(next.Snapshot.Resources),
			"v1_labelled": len(base.Labels), "v2_labelled": len(next.Labels),
		},
		"files_sha256": hashes,
		"command": fmt.Sprintf("go run ./cmd/aegis-datagen -seed %d -resources %d -modify %d -delete %d -add %d -captured-at %s",
			*seed, *resources, *modify, *del, *add, t0.Format(time.RFC3339)),
		"note": "Synthetic, fictional data. Contains deliberately insecure configurations for testing.",
	}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(*out, "manifest.json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d + %d resources to %s\n", len(base.Snapshot.Resources), len(next.Snapshot.Resources), *out)
	return nil
}
