// Package signing signs Aegis artefacts (released change sets, audit-log
// heads) with Ed25519 so that systems outside Aegis — a deployment pipeline,
// an auditor — can verify them with only the public key.
//
// Payloads are canonical JSON: encoding/json writes struct fields in
// declaration order and map keys sorted, and the exact signed bytes are
// returned to callers so verifiers never re-encode.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Signer holds a private key.
type Signer struct {
	priv      ed25519.PrivateKey
	KeyID     string // first 16 hex characters of SHA-256(public key)
	Ephemeral bool   // generated at start-up: signatures do not survive a restart
}

// PublicKey describes the verification key.
type PublicKey struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // base64 (standard), 32 bytes
	Ephemeral bool   `json:"ephemeral"`
}

// Signed is a payload with its detached signature.
type Signed struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"` // base64 (standard)
	KeyID     string          `json:"key_id"`
	Algorithm string          `json:"algorithm"`
}

// FromSeed builds a signer from a base64-encoded 32-byte seed.
func FromSeed(b64 string) (*Signer, error) {
	seed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("signing key must be a base64-encoded 32-byte Ed25519 seed")
	}
	return newSigner(ed25519.NewKeyFromSeed(seed), false), nil
}

// Ephemeral generates a throwaway key (development only).
func Ephemeral() *Signer {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return newSigner(priv, true)
}

// NewSeed returns a fresh base64 seed for AEGIS_SIGNING_KEY.
func NewSeed() string {
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	return base64.StdEncoding.EncodeToString(seed)
}

func newSigner(priv ed25519.PrivateKey, eph bool) *Signer {
	return &Signer{priv: priv, KeyID: keyID(priv.Public().(ed25519.PublicKey)), Ephemeral: eph}
}

func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Public returns the verification key.
func (s *Signer) Public() PublicKey {
	return PublicKey{Algorithm: "Ed25519", KeyID: s.KeyID, Ephemeral: s.Ephemeral,
		PublicKey: base64.StdEncoding.EncodeToString(s.priv.Public().(ed25519.PublicKey))}
}

// Sign encodes payload canonically and signs the bytes.
func (s *Signer) Sign(payload any) (Signed, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Signed{}, err
	}
	return Signed{Payload: raw, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, raw)),
		KeyID: s.KeyID, Algorithm: "Ed25519"}, nil
}

// Verify checks a signed payload against a base64 public key.
func Verify(publicKeyB64 string, sig Signed) error {
	pub, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("public key must be a base64-encoded 32-byte Ed25519 key")
	}
	if sig.KeyID != "" && sig.KeyID != keyID(pub) {
		return fmt.Errorf("signed with key %s, not with this public key (%s)", sig.KeyID, keyID(pub))
	}
	s, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return errors.New("signature is not base64")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), sig.Payload, s) {
		return errors.New("signature does not match the payload")
	}
	return nil
}
