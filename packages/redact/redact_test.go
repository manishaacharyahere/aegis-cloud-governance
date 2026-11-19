package redact

import (
	"reflect"
	"testing"
)

func TestIsSensitiveKey(t *testing.T) {
	for _, k := range []string{"password", "master_password", "DB_PASSWD", "client_secret", "private_key_pem", "access_key", "API_KEY", "token", "credentials"} {
		if !IsSensitiveKey(k) {
			t.Errorf("%q should be sensitive", k)
		}
	}
	for _, k := range []string{"bucket", "kms_key_id", "encryption", "username", "policy", "tags"} {
		if IsSensitiveKey(k) {
			t.Errorf("%q should not be sensitive", k)
		}
	}
}

func TestWalk(t *testing.T) {
	in := map[string]any{
		"db_password":                 "hunter2",
		"manage_master_user_password": true, // a setting, not a secret
		"api_key":                     "",   // nothing to hide
		"token":                       nil,
		"name":                        "orders",
		"nested":                      map[string]any{"client_secret": "s", "port": 5432.0},
		"list":                        []any{map[string]any{"access_key": "AKIA"}},
	}
	var paths []string
	out := Walk(in, "", &paths).(map[string]any)
	want := map[string]any{
		"db_password": Placeholder, "manage_master_user_password": true, "api_key": "", "token": nil, "name": "orders",
		"nested": map[string]any{"client_secret": Placeholder, "port": 5432.0},
		"list":   []any{map[string]any{"access_key": Placeholder}},
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("Walk = %v", out)
	}
	if !reflect.DeepEqual(paths, []string{"db_password", "list.access_key", "nested.client_secret"}) {
		t.Errorf("paths = %v", paths)
	}
	if in["db_password"] != "hunter2" {
		t.Error("Walk must not modify its input")
	}
	if m, ok := Walk(map[string]any(nil), "", nil).(map[string]any); !ok || m == nil {
		t.Error("a nil map must come back as an empty map")
	}
}
