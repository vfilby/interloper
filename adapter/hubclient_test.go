package adapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://hub.example":         true,
		"https://10.0.0.5:8740":       true,
		"http://127.0.0.1:8740":       true,
		"http://127.9.9.9":            true,
		"http://[::1]:8740/":          true,
		"http://localhost:8740":       true,
		"http://hub.example":          false,
		"http://10.0.0.5:8740":        false,
		"http://localhost.example":    false,
		"http://127.0.0.1.nip.io":     false,
		"ftp://127.0.0.1":             false,
		"127.0.0.1:8740":              false,
		"hub.example":                 false,
		"https://":                    false,
		"http://user@hub.example:80/": false,
	} {
		if err := CheckURL("-hub", raw); (err == nil) != ok {
			t.Errorf("%q: err %v, want ok %v", raw, err, ok)
		}
	}
}

// A hub error body reaches the log only as a short snippet.
func TestHubErrorBodyTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(strings.Repeat("x", 1<<20)))
	}))
	defer srv.Close()
	err := (&HubClient{Base: srv.URL}).Publish(context.Background(), PublishRequest{})
	if err == nil || len(err.Error()) > 300 || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("error of %d bytes: %.300v", len(err.Error()), err)
	}
}
