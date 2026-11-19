package access

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Verifier checks OIDC ID tokens. Provider discovery is lazy and retried, so
// the API can start before the identity provider; until discovery succeeds
// every token is rejected (fail closed).
type Verifier struct {
	Issuer   string
	ClientID string // expected audience
	HTTP     *http.Client
	Now      func() time.Time

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
	lastTry  time.Time
	inflight bool
}

// ErrProviderUnavailable means discovery has not succeeded yet.
var ErrProviderUnavailable = errors.New("identity provider unavailable")

// get returns the verifier, discovering the provider if needed. Discovery
// runs outside the lock: while it is in flight, other requests fail fast
// (503) instead of queueing behind a slow identity provider.
func (v *Verifier) get(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	v.mu.Lock()
	if v.verifier != nil {
		defer v.mu.Unlock()
		return v.verifier, nil
	}
	if v.inflight || time.Since(v.lastTry) < 2*time.Second {
		v.mu.Unlock()
		return nil, ErrProviderUnavailable
	}
	v.inflight, v.lastTry = true, time.Now()
	v.mu.Unlock()
	ver, err := v.discover(ctx)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.inflight = false
	if err != nil {
		return nil, err
	}
	v.verifier = ver
	return ver, nil
}

func (v *Verifier) discover(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	hc := v.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	dctx, cancel := context.WithTimeout(oidc.ClientContext(context.WithoutCancel(ctx), hc), 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(dctx, v.Issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderUnavailable, err)
	}
	cfg := &oidc.Config{ClientID: v.ClientID, SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256, oidc.EdDSA}}
	if v.Now != nil {
		cfg.Now = v.Now
	}
	// Key fetches must not be bound to the first request's context.
	return p.VerifierContext(oidc.ClientContext(context.Background(), hc), cfg), nil
}

// Verify validates a raw ID token and returns the caller.
func (v *Verifier) Verify(ctx context.Context, raw string) (Principal, error) {
	ver, err := v.get(ctx)
	if err != nil {
		return Principal{}, err
	}
	tok, err := ver.Verify(ctx, raw)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
	}
	var c struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := tok.Claims(&c); err != nil {
		return Principal{}, fmt.Errorf("%w: claims: %v", ErrUnauthenticated, err)
	}
	subject := "sub:" + tok.Subject
	if c.Email != "" && c.EmailVerified != nil && *c.EmailVerified {
		subject = CanonicalSubject(c.Email)
	}
	if !ValidSubject(subject) {
		return Principal{}, fmt.Errorf("%w: unusable subject", ErrUnauthenticated)
	}
	return Principal{Subject: subject, Name: c.Name, Method: "oidc"}, nil
}
