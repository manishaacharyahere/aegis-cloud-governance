package access

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type fakeIdP struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	down bool
}

func newIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{key: key}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.srv.URL, "jwks_uri": f.srv.URL + "/keys",
				"authorization_endpoint": f.srv.URL + "/auth", "token_endpoint": f.srv.URL + "/token",
				"id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) token(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifier(t *testing.T) {
	idp := newIdP(t)
	now := time.Now()
	base := func() map[string]any {
		return map[string]any{"iss": idp.srv.URL, "aud": "aegis-web", "sub": "user-1", "exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(), "email": "Alice@Example.com", "email_verified": true, "name": "Alice"}
	}
	v := &Verifier{Issuer: idp.srv.URL, ClientID: "aegis-web"}
	ctx := context.Background()

	p, err := v.Verify(ctx, idp.token(t, idp.key, base()))
	if err != nil || p.Subject != "alice@example.com" || p.Name != "Alice" || p.Method != "oidc" {
		t.Fatalf("valid token: %+v %v", p, err)
	}
	unverified := base()
	unverified["email_verified"] = false
	if p, err := v.Verify(ctx, idp.token(t, idp.key, unverified)); err != nil || p.Subject != "sub:user-1" {
		t.Errorf("unverified email must fall back to the subject: %+v %v", p, err)
	}

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad := map[string]func(map[string]any){
		"expired":        func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() },
		"wrong audience": func(c map[string]any) { c["aud"] = "someone-else" },
		"wrong issuer":   func(c map[string]any) { c["iss"] = "https://evil.example" },
	}
	for name, mutate := range bad {
		c := base()
		mutate(c)
		if _, err := v.Verify(ctx, idp.token(t, idp.key, c)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if _, err := v.Verify(ctx, idp.token(t, other, base())); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("token signed by another key accepted: %v", err)
	}
	if _, err := v.Verify(ctx, "not-a-jwt"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("garbage accepted: %v", err)
	}
	none := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."
	if _, err := v.Verify(ctx, none); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("alg=none accepted: %v", err)
	}

	// Provider down at first use: fail closed, then recover once it is back.
	idp2 := newIdP(t)
	idp2.down = true
	v2 := &Verifier{Issuer: idp2.srv.URL, ClientID: "aegis-web"}
	c := base()
	c["iss"] = idp2.srv.URL
	tok := idp2.token(t, idp2.key, c)
	if _, err := v2.Verify(ctx, tok); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("provider down: %v", err)
	}
	idp2.down = false
	v2.lastTry = time.Time{} // skip the retry delay
	if _, err := v2.Verify(ctx, tok); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

func TestRolesAndSubjects(t *testing.T) {
	for _, tc := range []struct {
		roles []string
		p     Permission
		want  bool
	}{
		{[]string{RoleViewer}, Read, true},
		{[]string{RoleViewer}, Operate, false},
		{[]string{RoleAnalyst}, Operate, true},
		{[]string{RoleAnalyst}, Approve, false},
		{[]string{RoleApprover}, Approve, true},
		{[]string{RoleApprover}, Operate, false},
		{[]string{RoleAdmin}, Admin, true},
		{[]string{"superuser"}, Read, false},
		{nil, Read, false},
	} {
		if got := Allows(tc.roles, tc.p); got != tc.want {
			t.Errorf("%v %s = %v", tc.roles, tc.p, got)
		}
	}
	for s, ok := range map[string]bool{"alice@example.com": true, "sub:abc|123": true, "Alice@example.com": false,
		"alice": false, "sub:": false, "x@y": false} {
		if ValidSubject(s) != ok {
			t.Errorf("ValidSubject(%q) != %v", s, ok)
		}
	}
}
