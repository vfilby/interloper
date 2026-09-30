package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPushover(t *testing.T) {
	var got url.Values
	status := `{"status":1}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		got = r.PostForm
		io.WriteString(w, status)
	}))
	defer srv.Close()
	p := &Pushover{Endpoint: srv.URL, Token: "secret-app-token", User: "usr"}

	err := p.Send(context.Background(), Message{Title: "t", Body: strings.Repeat("x", 2000), URL: "https://u", URLTitle: "open",
		Priority: 2, TTL: 90 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"token": "secret-app-token", "user": "usr", "title": "t", "url": "https://u",
		"url_title": "open", "priority": "0", "ttl": "90"} {
		if got.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, got.Get(k), want)
		}
	}
	if n := len([]rune(got.Get("message"))); n != 1024 {
		t.Errorf("message not clipped to 1024 runes: %d", n)
	}

	if err := p.Send(context.Background(), Message{Title: "t", Body: "b"}); err != nil || got.Has("url") || got.Has("ttl") {
		t.Errorf("url/ttl sent when unset: %v (%v)", got, err)
	}

	status = `{"status":0,"errors":["application token is invalid"]}`
	err = p.Send(context.Background(), Message{Title: "t", Body: "b"})
	if err == nil || strings.Contains(err.Error(), "secret-app-token") {
		t.Errorf("want an error that does not carry the token, got %v", err)
	}
}
