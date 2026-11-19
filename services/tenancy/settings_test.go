package tenancy

import (
	"errors"
	"fmt"
	"testing"
)

func n[T any](count int, f func(i int) T) []T {
	out := make([]T, count)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

// One invalid field per case, so each check is proven on its own.
func TestValidate(t *testing.T) {
	valid := PolicyConfig{ApprovedRegions: []string{"ap-south-1", "eu-west-1"}, RequiredTags: []string{"owner", "cost_center"},
		AdminPorts: []int{22, 3389}, ApprovedEncryption: []string{"aws:kms"}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := (PolicyConfig{}).Validate(); err != nil {
		t.Fatalf("empty config (all defaults) rejected: %v", err)
	}
	tags := func(k int) []string { return n(k, func(i int) string { return fmt.Sprintf("tag%d", i) }) }
	ports := func(k int) []int { return n(k, func(i int) int { return 1000 + i }) }
	encs := func(k int) []string { return n(k, func(i int) string { return fmt.Sprintf("enc%d", i) }) }
	manyRegions := n(51, func(i int) string { return fmt.Sprintf("eu-west%s-%d", string(rune('a'+i/10)), i%10) })
	cases := map[string]PolicyConfig{
		"region format":       {ApprovedRegions: []string{"Mars-1"}},
		"region duplicate":    {ApprovedRegions: []string{"eu-west-1", "eu-west-1"}},
		"too many regions":    {ApprovedRegions: manyRegions},
		"tag format":          {RequiredTags: []string{"has space"}},
		"too many tags":       {RequiredTags: tags(21)},
		"port range low":      {AdminPorts: []int{0}},
		"port range high":     {AdminPorts: []int{70000}},
		"too many ports":      {AdminPorts: ports(21)},
		"encryption format":   {ApprovedEncryption: []string{"aes 256"}},
		"too many encryption": {ApprovedEncryption: encs(11)},
	}
	for name, c := range cases {
		if err := c.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	// The boundaries themselves are allowed.
	if err := (PolicyConfig{RequiredTags: tags(20), AdminPorts: ports(20), ApprovedEncryption: encs(10), ApprovedRegions: manyRegions[:50]}).Validate(); err != nil {
		t.Errorf("configuration at the limits rejected: %v", err)
	}
}

func TestSHA256IsStable(t *testing.T) {
	a := PolicyConfig{RequiredTags: []string{"owner"}, AdminPorts: []int{22}}
	b := PolicyConfig{RequiredTags: []string{"owner"}, AdminPorts: []int{22}}
	if a.SHA256() != b.SHA256() || len(a.SHA256()) != 64 {
		t.Fatal("equal configurations must hash equally")
	}
	if a.SHA256() == (PolicyConfig{RequiredTags: []string{"team"}, AdminPorts: []int{22}}).SHA256() {
		t.Fatal("different configurations hash equally")
	}
}
