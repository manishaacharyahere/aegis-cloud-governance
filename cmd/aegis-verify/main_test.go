package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manishaacharyahere/aegis-cloud-governance/packages/signing"
)

func TestVerifyShapes(t *testing.T) {
	s := signing.Ephemeral()
	sig, _ := s.Sign(map[string]any{"type": "aegis.changeset/v1", "plan_sha256": "abc"})
	dir := t.TempDir()
	write := func(name string, v any) string {
		raw, _ := json.Marshal(v)
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, raw, 0o600)
		return p
	}
	pub := s.Public().PublicKey
	for name, doc := range map[string]any{
		"bare.json":        sig,
		"changeset.json":   map[string]any{"signed": sig},
		"remediation.json": map[string]any{"id": "r1", "change_set": map[string]any{"signed": sig}},
	} {
		var out bytes.Buffer
		if err := run([]string{"-key", pub, write(name, doc)}, &out); err != nil || !strings.HasPrefix(out.String(), "OK: valid aegis.changeset/v1") {
			t.Errorf("%s: %v %s", name, err, out.String())
		}
	}
	tampered := sig
	tampered.Payload = json.RawMessage(`{"plan_sha256":"evil","type":"aegis.changeset/v1"}`)
	if err := run([]string{"-key", pub, write("bad.json", tampered)}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "INVALID") {
		t.Errorf("tampered change set: %v", err)
	}
	if err := run([]string{"-key", pub, write("unreleased.json", map[string]any{"id": "x"})}, &bytes.Buffer{}); err == nil {
		t.Error("unsigned document accepted")
	}
	var out bytes.Buffer
	if err := run([]string{"-new-key"}, &out); err != nil || !strings.Contains(out.String(), "AEGIS_SIGNING_KEY=") {
		t.Errorf("new key: %v", err)
	}
}
