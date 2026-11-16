package signing

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	seed := NewSeed()
	s, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := FromSeed(seed)
	if again.KeyID != s.KeyID || s.Ephemeral {
		t.Fatal("same seed must give the same key")
	}
	sig, err := s.Sign(map[string]any{"b": 1, "a": []string{"x"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(sig.Payload) != `{"a":["x"],"b":1}` {
		t.Errorf("payload is not canonical: %s", sig.Payload)
	}
	pub := s.Public().PublicKey
	if err := Verify(pub, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	tampered := sig
	tampered.Payload = json.RawMessage(`{"a":["x"],"b":2}`)
	if err := Verify(pub, tampered); err == nil {
		t.Error("tampered payload accepted")
	}
	other := Ephemeral()
	if err := Verify(other.Public().PublicKey, sig); err == nil || !strings.Contains(err.Error(), "not with this public key") {
		t.Errorf("wrong key: %v", err)
	}
	forged, _ := other.Sign(map[string]any{"a": []string{"x"}, "b": 1})
	forged.KeyID = s.KeyID
	if err := Verify(pub, forged); err == nil {
		t.Error("signature by another key accepted")
	}
	for _, bad := range []string{"", "not-base64!", "AAAA"} {
		if _, err := FromSeed(bad); err == nil {
			t.Errorf("bad seed %q accepted", bad)
		}
	}
}
