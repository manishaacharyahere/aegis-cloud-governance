package opa

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

// fakeOPA fails every resource whose type is "bad" with two rules (one
// deny, one warn, the deny reported twice), and counts the requests.
type fakeOPA struct {
	calls  int
	sizes  []int
	err    error
	config map[string]any
}

func (f *fakeOPA) Query(_ context.Context, path string, input any, out any) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	in := input.(map[string]any)
	f.config = in["config"].(map[string]any)
	rs := in["resources"].([]Resource)
	f.sizes = append(f.sizes, len(rs))
	res := map[string][]Finding{"deny": {}, "warn": {}}
	for _, r := range rs {
		if r.Type == "bad" {
			res["deny"] = append(res["deny"], Finding{RuleID: "R-2", Address: r.ID}, Finding{RuleID: "R-2", Address: r.ID})
			res["warn"] = append(res["warn"], Finding{RuleID: "R-1", Address: r.ID})
		}
	}
	raw, _ := json.Marshal(res)
	return json.Unmarshal(raw, out)
}

func (f *fakeOPA) Bundle(context.Context) (Bundle, error) { return Bundle{}, nil }

func TestEvaluateInventoryChunksAndGroups(t *testing.T) {
	rs := make([]Resource, ChunkSize+5)
	for i := range rs {
		rs[i] = Resource{ID: "r" + string(rune('a'+i%26)) + string(rune('0'+i/26%10)), Type: "ok"}
	}
	rs[0] = Resource{ID: "bucket", Type: "bad"}
	f := &fakeOPA{}
	findings, err := EvaluateInventory(context.Background(), f, rs, map[string]any{"admin_ports": []int{22}})
	if err != nil {
		t.Fatal(err)
	}
	if f.calls != 2 || !reflect.DeepEqual(f.sizes, []int{ChunkSize, 5}) {
		t.Errorf("requests %d with sizes %v, want 2 chunks", f.calls, f.sizes)
	}
	if f.config["admin_ports"] == nil {
		t.Error("tenant configuration was not passed to the policies")
	}
	if got := FailingRules(findings); !reflect.DeepEqual(got, map[string][]string{"bucket": {"R-1", "R-2"}}) {
		t.Errorf("failing rules = %v (sorted, de-duplicated, warn included)", got)
	}
}

func TestEvaluateInventoryKeepsTheCause(t *testing.T) {
	down := &UnavailableError{Err: errors.New("connection refused")}
	_, err := EvaluateInventory(context.Background(), &fakeOPA{err: down}, []Resource{{ID: "x"}}, nil)
	var u *UnavailableError
	if !errors.As(err, &u) {
		t.Fatalf("an unavailable OPA must stay recognisable (callers answer 503): %v", err)
	}
	if got, err := EvaluateInventory(context.Background(), &fakeOPA{}, nil, nil); err != nil || len(got) != 0 {
		t.Fatalf("no resources: %v %v", got, err)
	}
}
