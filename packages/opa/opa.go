// Package opa is a minimal client for the Open Policy Agent REST API.
package opa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ErrUndefined means the queried document does not exist (policy not loaded).
var ErrUndefined = errors.New("opa: policy document is undefined (is the policy loaded?)")

// UnavailableError marks transport and 5xx failures, which are retryable.
type UnavailableError struct{ Err error }

func (e *UnavailableError) Error() string { return e.Err.Error() }
func (e *UnavailableError) Unwrap() error { return e.Err }

// Client talks to one OPA server.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.BaseURL, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return &UnavailableError{fmt.Errorf("opa request: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return &UnavailableError{fmt.Errorf("opa returned %s", resp.Status)}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("opa returned %s", resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out); err != nil {
		return fmt.Errorf("decode opa response: %w", err)
	}
	return nil
}

// Query evaluates data.<path> (dot-separated, e.g. "aegis.terraform") with
// input and decodes the result into out. It fails closed with ErrUndefined.
func (c *Client) Query(ctx context.Context, path string, input any, out any) error {
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/data/"+strings.ReplaceAll(path, ".", "/"), map[string]any{"input": input}, &resp); err != nil {
		return err
	}
	if len(resp.Result) == 0 || string(resp.Result) == "null" {
		return ErrUndefined
	}
	return json.Unmarshal(resp.Result, out)
}

// Bundle identifies the exact policy text OPA is serving.
type Bundle struct {
	SHA256  string            `json:"sha256"`
	Modules map[string]string `json:"modules"` // module id -> raw Rego
}

// Bundle fetches the loaded policy modules (excluding *_test.rego) and
// hashes them independently of mount paths and ordering.
func (c *Client) Bundle(ctx context.Context) (Bundle, error) {
	var resp struct {
		Result []struct {
			ID  string `json:"id"`
			Raw string `json:"raw"`
		} `json:"result"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/policies", nil, &resp); err != nil {
		return Bundle{}, err
	}
	b := Bundle{Modules: map[string]string{}}
	var digests []string
	for _, m := range resp.Result {
		if strings.HasSuffix(m.ID, "_test.rego") {
			continue
		}
		b.Modules[m.ID] = m.Raw
		d := sha256.Sum256([]byte(m.Raw))
		digests = append(digests, hex.EncodeToString(d[:]))
	}
	if len(digests) == 0 {
		return Bundle{}, ErrUndefined
	}
	sort.Strings(digests)
	sum := sha256.Sum256([]byte(strings.Join(digests, "\n")))
	b.SHA256 = hex.EncodeToString(sum[:])
	return b, nil
}
