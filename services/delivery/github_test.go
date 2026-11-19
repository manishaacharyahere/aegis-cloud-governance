package delivery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeGitHub implements the few REST endpoints Open uses, with real
// conflict answers (422) for existing branches and pull requests.
type fakeGitHub struct {
	mu       sync.Mutex
	branches map[string]bool
	files    map[string]string // branch + ":" + path -> content
	writes   int
	prs      map[string]int // head branch -> number
	auth     []string
}

func newFake() *fakeGitHub {
	return &fakeGitHub{branches: map[string]bool{"main": true}, files: map[string]string{}, prs: map[string]int{}}
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	p := strings.TrimPrefix(r.URL.Path, "/repos/acme/infra")
	reply := func(code int, v any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	var in map[string]string
	_ = json.NewDecoder(r.Body).Decode(&in)
	switch {
	case r.Method == "GET" && p == "":
		reply(200, map[string]string{"default_branch": "main"})
	case r.Method == "GET" && p == "/git/ref/heads/main":
		reply(200, map[string]any{"object": map[string]string{"sha": "abc123"}})
	case r.Method == "POST" && p == "/git/refs":
		b := strings.TrimPrefix(in["ref"], "refs/heads/")
		if f.branches[b] {
			reply(422, map[string]string{"message": "Reference already exists"})
			return
		}
		f.branches[b] = true
		reply(201, map[string]string{})
	case r.Method == "GET" && strings.HasPrefix(p, "/contents/"):
		key := r.URL.Query().Get("ref") + ":" + strings.TrimPrefix(p, "/contents/")
		c, ok := f.files[key]
		if !ok {
			reply(404, map[string]string{"message": "Not Found"})
			return
		}
		reply(200, map[string]string{"sha": "f1", "content": base64.StdEncoding.EncodeToString([]byte(c))})
	case r.Method == "PUT" && strings.HasPrefix(p, "/contents/"):
		raw, _ := base64.StdEncoding.DecodeString(in["content"])
		f.files[in["branch"]+":"+strings.TrimPrefix(p, "/contents/")] = string(raw)
		f.writes++
		reply(201, map[string]string{})
	case r.Method == "POST" && p == "/pulls":
		if _, ok := f.prs[in["head"]]; ok {
			reply(422, map[string]string{"message": "A pull request already exists"})
			return
		}
		f.prs[in["head"]] = len(f.prs) + 1
		reply(201, map[string]any{"html_url": "https://github.example/acme/infra/pull/1", "number": f.prs[in["head"]]})
	case r.Method == "GET" && p == "/pulls":
		n := f.prs[strings.TrimPrefix(r.URL.Query().Get("head"), "acme:")]
		reply(200, []map[string]any{{"html_url": "https://github.example/acme/infra/pull/1", "number": n}})
	default:
		reply(404, map[string]string{"message": "unexpected " + r.Method + " " + p})
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	fake := newFake()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	g := &GitHub{API: srv.URL, Repo: "acme/infra", Token: "secret-token"}
	c := Change{Branch: "aegis/remediation-1", Path: "aegis/change-sets/1.json", Content: []byte(`{"plan":"x"}`), Title: "t", Body: "b"}
	first, err := g.Open(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	again, err := g.Open(context.Background(), c)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if first.Number != 1 || again != first {
		t.Errorf("first %+v, retry %+v", first, again)
	}
	if fake.writes != 1 || len(fake.prs) != 1 || fake.files["aegis/remediation-1:aegis/change-sets/1.json"] != `{"plan":"x"}` {
		t.Errorf("writes=%d prs=%d files=%v", fake.writes, len(fake.prs), fake.files)
	}
	for _, a := range fake.auth {
		if a != "Bearer secret-token" {
			t.Fatalf("authorization header %q", a)
		}
	}
}

func TestOpenErrorsNeverContainTheToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()
	_, err := (&GitHub{API: srv.URL, Repo: "acme/infra", Token: "ghp_secret"}).Open(context.Background(), Change{Branch: "b", Path: "p"})
	if err == nil || strings.Contains(err.Error(), "ghp_secret") || !strings.Contains(err.Error(), "Bad credentials") {
		t.Fatalf("err = %v", err)
	}
	if _, err := (&GitHub{Repo: "not a repo", Token: "x"}).Open(context.Background(), Change{}); err != ErrNotConfigured {
		t.Fatalf("bad repo: %v", err)
	}
}
