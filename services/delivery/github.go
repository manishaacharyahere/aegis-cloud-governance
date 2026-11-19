// Package delivery hands released change sets to the team's own workflow.
// GitHub opens a pull request that adds the signed change set to a
// repository, so the change is reviewed and applied by the team's pipeline;
// Aegis itself never holds cloud credentials or changes infrastructure.
package delivery

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Change is one change set to deliver.
type Change struct {
	Branch  string // e.g. aegis/remediation-<id>
	Path    string // file to add, e.g. aegis/change-sets/<id>.json
	Content []byte
	Title   string
	Body    string // pull request description (Markdown)
}

// PullRequest is the delivered result.
type PullRequest struct {
	URL    string `json:"url"`
	Number int    `json:"number"`
}

// ErrNotConfigured: no repository or token.
var ErrNotConfigured = errors.New("delivery is not configured")

// GitHub opens pull requests through the REST API with a fine-grained token
// limited to one repository (Contents and Pull requests: read and write).
type GitHub struct {
	API   string // default https://api.github.com
	Repo  string // owner/name
	Token string
	HTTP  *http.Client
}

var repoRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$`)

// Configured reports whether pull requests can be opened.
func (g *GitHub) Configured() bool { return g != nil && g.Token != "" && repoRe.MatchString(g.Repo) }

// Open adds c.Path on c.Branch and opens a pull request to the default
// branch. Every step is idempotent: an existing branch, file or open pull
// request is reused, so a retry (or two concurrent calls) ends with one
// pull request.
func (g *GitHub) Open(ctx context.Context, c Change) (PullRequest, error) {
	if !g.Configured() {
		return PullRequest{}, ErrNotConfigured
	}
	var repo struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := g.call(ctx, http.MethodGet, "", nil, &repo); err != nil {
		return PullRequest{}, err
	}
	var head struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := g.call(ctx, http.MethodGet, "/git/ref/heads/"+url.PathEscape(repo.DefaultBranch), nil, &head); err != nil {
		return PullRequest{}, err
	}
	err := g.call(ctx, http.MethodPost, "/git/refs", map[string]string{"ref": "refs/heads/" + c.Branch, "sha": head.Object.SHA}, nil)
	if err != nil && !isStatus(err, http.StatusUnprocessableEntity) { // 422: the branch exists
		return PullRequest{}, err
	}
	put := map[string]string{"message": c.Title, "branch": c.Branch, "content": base64.StdEncoding.EncodeToString(c.Content)}
	var existing struct {
		SHA     string `json:"sha"`
		Content string `json:"content"`
	}
	switch err := g.call(ctx, http.MethodGet, "/contents/"+escapePath(c.Path)+"?ref="+url.QueryEscape(c.Branch), nil, &existing); {
	case err == nil:
		put["sha"] = existing.SHA
	case !isStatus(err, http.StatusNotFound):
		return PullRequest{}, err
	}
	if same, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(existing.Content, "\n", "")); existing.SHA == "" || !bytes.Equal(same, c.Content) {
		if err := g.call(ctx, http.MethodPut, "/contents/"+escapePath(c.Path), put, nil); err != nil {
			return PullRequest{}, err
		}
	}
	var pr struct {
		HTMLURL string `json:"html_url"`
		Number  int    `json:"number"`
	}
	err = g.call(ctx, http.MethodPost, "/pulls", map[string]string{"title": c.Title, "head": c.Branch, "base": repo.DefaultBranch, "body": c.Body}, &pr)
	if isStatus(err, http.StatusUnprocessableEntity) { // already open: find it
		var open []struct {
			HTMLURL string `json:"html_url"`
			Number  int    `json:"number"`
		}
		owner := strings.SplitN(g.Repo, "/", 2)[0]
		if err := g.call(ctx, http.MethodGet, "/pulls?state=open&head="+url.QueryEscape(owner+":"+c.Branch), nil, &open); err != nil {
			return PullRequest{}, err
		}
		if len(open) == 0 {
			return PullRequest{}, fmt.Errorf("github: pull request for %s could not be created or found", c.Branch)
		}
		return PullRequest{URL: open[0].HTMLURL, Number: open[0].Number}, nil
	}
	if err != nil {
		return PullRequest{}, err
	}
	return PullRequest{URL: pr.HTMLURL, Number: pr.Number}, nil
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// StatusError is a GitHub API answer other than 2xx. It never contains the token.
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string { return fmt.Sprintf("github: HTTP %d: %s", e.Status, e.Message) }

func isStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Status == code
}

func (g *GitHub) call(ctx context.Context, method, path string, in, out any) error {
	api := strings.TrimRight(g.API, "/")
	if api == "" {
		api = "https://api.github.com"
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, api+"/repos/"+g.Repo+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := g.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	res, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) { // keep the cause, never the URL with its query
			return fmt.Errorf("github: %s %s: %w", method, path, ue.Err)
		}
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		return &StatusError{Status: res.StatusCode, Message: e.Message}
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
