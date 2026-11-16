// Command aegis-verify checks Aegis signatures outside Aegis, e.g. in a
// deployment pipeline before applying a released change set.
//
//	go run ./cmd/aegis-verify -new-key                       # print a new AEGIS_SIGNING_KEY and its public key
//	go run ./cmd/aegis-verify -key <public key> file.json    # verify a signed change set or audit head
//
// file.json may be the signed object itself ({"payload","signature",...}),
// a change set ({"signed": {...}}) or a whole remediation from the API
// ({"change_set": {"signed": {...}}}). The public key comes from
// GET /api/v1/signing-key and should be pinned in the pipeline.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/signing"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "aegis-verify:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("aegis-verify", flag.ContinueOnError)
	newKey := fs.Bool("new-key", false, "print a new signing seed and its public key")
	key := fs.String("key", "", "base64 Ed25519 public key (from GET /api/v1/signing-key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *newKey {
		seed := signing.NewSeed()
		s, _ := signing.FromSeed(seed)
		_, err := fmt.Fprintf(out, "AEGIS_SIGNING_KEY=%s\npublic_key=%s\nkey_id=%s\n", seed, s.Public().PublicKey, s.KeyID)
		return err
	}
	if *key == "" || fs.NArg() != 1 {
		return errors.New("usage: aegis-verify -key <public key> <file.json>   or   aegis-verify -new-key")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	sig, err := extract(raw)
	if err != nil {
		return err
	}
	if err := signing.Verify(*key, sig); err != nil {
		return fmt.Errorf("INVALID: %w", err)
	}
	var payload map[string]any
	_ = json.Unmarshal(sig.Payload, &payload)
	_, err = fmt.Fprintf(out, "OK: valid %v signed by key %s\n%s\n", payload["type"], sig.KeyID, sig.Payload)
	return err
}

// extract finds the signed object in any of the accepted shapes.
func extract(raw []byte) (signing.Signed, error) {
	var bare signing.Signed
	var doc struct {
		Signed    *signing.Signed `json:"signed"`
		ChangeSet *struct {
			Signed *signing.Signed `json:"signed"`
		} `json:"change_set"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return signing.Signed{}, fmt.Errorf("not JSON: %w", err)
	}
	_ = json.Unmarshal(raw, &bare)
	switch {
	case doc.ChangeSet != nil && doc.ChangeSet.Signed != nil:
		return *doc.ChangeSet.Signed, nil
	case doc.Signed != nil:
		return *doc.Signed, nil
	case bare.Signature != "":
		return bare, nil
	}
	return signing.Signed{}, errors.New("no signature found (is the change set released?)")
}
