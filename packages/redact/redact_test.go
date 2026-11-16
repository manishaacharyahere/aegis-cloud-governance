package redact

import "testing"

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
