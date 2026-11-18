package automation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A webhook URL's path is its secret: failures must not echo it.
func TestWebhookErrorHidesURL(t *testing.T) {
	w := Webhook{URL: "http://127.0.0.1:1/services/T000/B000/s3cr3t-token"}
	err := w.Notify(context.Background(), "hello")
	if err == nil {
		t.Fatal("expected a connection error")
	}
	if strings.Contains(err.Error(), "s3cr3t-token") || strings.Contains(err.Error(), "/services/") {
		t.Fatalf("error leaks the webhook URL: %v", err)
	}
}

// Imported names cannot become links or mentions in chat.
func TestWebhookEscapesMarkup(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]string
		_ = json.Unmarshal(b, &m)
		got = m["text"]
	}))
	defer srv.Close()
	if err := (Webhook{URL: srv.URL}).Notify(context.Background(), "bucket <https://evil|click> & <!channel>"); err != nil {
		t.Fatal(err)
	}
	if got != "bucket &lt;https://evil|click&gt; &amp; &lt;!channel&gt;" {
		t.Fatalf("text = %q", got)
	}
}
