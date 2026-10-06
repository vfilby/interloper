// Package mpapi is the small part of Mailpit's REST API the mail adapter uses, as of Mailpit 1.31.
//
// The login is an ordinary Mailpit UI user (MP_UI_AUTH_FILE). Mailpit has no narrower role: that login can read,
// release, tag and delete every message, so it is the adapter's credential and stays in its secrets directory.
//
// Nothing here calls GET /api/v1/message/{ID}: that marks the message read, and held mail should look unread in the UI.
// Summaries come from search, the body from /raw, neither of which changes the message.
package mpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNotFound: Mailpit has no message with that id (deleted, or never existed).
var ErrNotFound = errors.New("message not found in Mailpit")

// ErrUnauthorized: Mailpit rejected the login.
var ErrUnauthorized = errors.New("Mailpit rejected the adapter's login")

type Address struct {
	Name    string `json:"Name"`
	Address string `json:"Address"`
}

// Message is Mailpit's message summary. Bcc holds the envelope recipients that are in no header, so To+Cc+Bcc is
// everyone a release would send to.
type Message struct {
	ID          string    `json:"ID"`
	MessageID   string    `json:"MessageID"`
	Read        bool      `json:"Read"`
	From        *Address  `json:"From"`
	To          []Address `json:"To"`
	Cc          []Address `json:"Cc"`
	Bcc         []Address `json:"Bcc"`
	ReplyTo     []Address `json:"ReplyTo"`
	Subject     string    `json:"Subject"`
	Created     time.Time `json:"Created"`
	Tags        []string  `json:"Tags"`
	Size        int64     `json:"Size"`
	Attachments int       `json:"Attachments"`
	Snippet     string    `json:"Snippet"`
}

// HasTag reports whether the message carries tag exactly.
func (m Message) HasTag(tag string) bool {
	for _, t := range m.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

type Client struct {
	base       string
	user, pass string
	http       *http.Client
}

// New returns a client for base (e.g. http://127.0.0.1:8025). hc may be nil. A release goes through the upstream SMTP
// relay while the request waits, so the default timeout is generous.
func New(base, user, pass string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	return &Client{base: strings.TrimRight(base, "/"), user: user, pass: pass, http: hc}
}

const maxJSON = 16 << 20

// MaxRaw bounds a raw message read; Mailpit's own default SMTP size limit is 30 MB.
const MaxRaw = 40 << 20

func (c *Client) req(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.pass)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		resp.Body.Close()
		return nil, fmt.Errorf("%s %s: HTTP %d: %w", method, path, resp.StatusCode, ErrUnauthorized)
	case resp.StatusCode == http.StatusNotFound:
		resp.Body.Close()
		return nil, fmt.Errorf("%s %s: %w", method, path, ErrNotFound)
	case resp.StatusCode/100 != 2:
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, snippet(data))
	}
	return resp, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	resp, err := c.req(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJSON))
	if err != nil {
		return fmt.Errorf("%s %s: reading body: %w", method, path, err)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s %s: decoding response: %w", method, path, err)
		}
	}
	return nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

const page = 250

// Tagged lists every message carrying tag, newest first. The search is server-side; the tag is checked again here.
func (c *Client) Tagged(ctx context.Context, tag string) ([]Message, error) {
	var out []Message
	for start := 0; ; start += page {
		var res struct {
			Messages []Message `json:"messages"`
		}
		q := url.Values{"query": {"tag:" + tag}, "start": {fmt.Sprint(start)}, "limit": {fmt.Sprint(page)}}
		if err := c.do(ctx, http.MethodGet, "/api/v1/search?"+q.Encode(), nil, &res); err != nil {
			return nil, err
		}
		for _, m := range res.Messages {
			if m.HasTag(tag) {
				out = append(out, m)
			}
		}
		if len(res.Messages) < page {
			return out, nil
		}
	}
}

// Raw returns the message source exactly as received.
func (c *Client) Raw(ctx context.Context, id string) ([]byte, error) {
	path := "/api/v1/message/" + url.PathEscape(id) + "/raw"
	resp, err := c.req(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxRaw+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: reading body: %w", path, err)
	}
	if len(b) > MaxRaw {
		return nil, fmt.Errorf("GET %s: message larger than %d bytes", path, MaxRaw)
	}
	return b, nil
}

// SetTags replaces the message's tags with tags.
func (c *Client) SetTags(ctx context.Context, id string, tags []string) error {
	return c.do(ctx, http.MethodPut, "/api/v1/tags", map[string]any{"IDs": []string{id}, "Tags": tags}, nil)
}

// Release sends the stored message through Mailpit's SMTP relay to exactly to.
func (c *Client) Release(ctx context.Context, id string, to []string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/message/"+url.PathEscape(id)+"/release", map[string]any{"To": to}, nil)
}
