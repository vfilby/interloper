// Package notify sends notifications. Phase 1: Pushover only (a stopgap; APNs from the broker replaces it).
// Pushover sees everything in a message, so messages carry names, durations and reasons, never secrets.
package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Message struct {
	Title    string
	Body     string
	URL      string
	URLTitle string
	Priority int           // -1 quiet, 0 normal; never above 0 (1 would bypass quiet hours)
	TTL      time.Duration // Pushover deletes the message after this; 0 = keep
}

type Notifier interface {
	Send(ctx context.Context, m Message) error
}

const PushoverEndpoint = "https://api.pushover.net/1/messages.json"

type Pushover struct {
	Endpoint string
	Token    string // application token
	User     string // user or group key
	HTTP     *http.Client
}

func (p *Pushover) Send(ctx context.Context, m Message) error {
	form := url.Values{
		"token":    {p.Token},
		"user":     {p.User},
		"title":    {Clip(m.Title, 250)},
		"message":  {Clip(m.Body, 1024)},
		"priority": {strconv.Itoa(min(m.Priority, 0))},
	}
	if m.URL != "" {
		form.Set("url", Clip(m.URL, 512))
		form.Set("url_title", Clip(m.URLTitle, 100))
	}
	if secs := int(m.TTL.Seconds()); secs > 0 {
		form.Set("ttl", strconv.Itoa(secs))
	}
	endpoint := p.Endpoint
	if endpoint == "" {
		endpoint = PushoverEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hc := p.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		// url.Error would print the endpoint only; the token travels in the body, never in the URL
		return fmt.Errorf("pushover: %w", err)
	}
	defer resp.Body.Close()
	var r struct {
		Status int      `json:"status"`
		Errors []string `json:"errors"`
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = json.Unmarshal(data, &r)
	if resp.StatusCode != http.StatusOK || r.Status != 1 {
		return fmt.Errorf("pushover: HTTP %d %v", resp.StatusCode, r.Errors)
	}
	return nil
}

// Clip cuts s to at most n runes, marking the cut.
func Clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
