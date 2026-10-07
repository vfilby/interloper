package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vfilby/interpose/internal/protocol"
)

// HubClient is the adapter's side of the hub API. The token only gets it onto the hub; nothing it sends is
// trusted for being sent by it.
type HubClient struct {
	Base  string
	Token string
	HTTP  *http.Client
}

type PublishRequest struct {
	ID        string                     `json:"id"`
	Kind      string                     `json:"kind"`
	CreatedAt int64                      `json:"created_at"`
	ExpiresAt int64                      `json:"expires_at"`
	Boxes     map[string]protocol.Sealed `json:"boxes"`
}

type QueuedDecision struct {
	Adapter   string            `json:"adapter"`
	RequestID string            `json:"request_id"`
	DeviceID  string            `json:"device_id"`
	Decision  protocol.Envelope `json:"decision"`
}

func (h *HubClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(h.Base, "/")+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+h.Token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	c := h.HTTP
	if c == nil {
		c = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("hub %s %s: HTTP %d: %s", method, path, resp.StatusCode, snippet(data))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// snippet is as much of an error body as goes into a log line.
func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// CheckURL accepts https, and plain http only to a loopback host (an IP literal or localhost): a token, decisions or a
// service credential must not cross the network in the clear.
func CheckURL(what, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s %q: %w", what, raw, err)
	}
	switch {
	case u.Host == "":
		return fmt.Errorf("%s %q: want an absolute URL such as https://host", what, raw)
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http":
		h := u.Hostname()
		if ip := net.ParseIP(h); h == "localhost" || (ip != nil && ip.IsLoopback()) {
			return nil
		}
		return fmt.Errorf("%s %q: plain http is only allowed to a loopback address; use https", what, raw)
	default:
		return fmt.Errorf("%s %q: scheme must be https (or http to a loopback address)", what, raw)
	}
}

func (h *HubClient) Publish(ctx context.Context, r PublishRequest) error {
	return h.do(ctx, http.MethodPost, "/v1/adapter/requests", r, nil)
}

// Decisions long-polls for up to wait.
func (h *HubClient) Decisions(ctx context.Context, wait time.Duration) ([]QueuedDecision, error) {
	var out []QueuedDecision
	err := h.do(ctx, http.MethodGet, fmt.Sprintf("/v1/adapter/decisions?wait=%d", int(wait.Seconds())), nil, &out)
	return out, err
}

func (h *HubClient) Ack(ctx context.Context, requestID string, ack protocol.Envelope) error {
	return h.do(ctx, http.MethodPost, "/v1/adapter/acks", map[string]any{"request_id": requestID, "ack": ack}, nil)
}

// Roster fetches a user's roster chain. Not trusted: Trust verifies it against the pin.
func (h *HubClient) Roster(ctx context.Context, user string) ([]protocol.Envelope, error) {
	var out struct {
		Chain []protocol.Envelope `json:"chain"`
	}
	err := h.do(ctx, http.MethodGet, "/v1/adapter/rosters?user="+url.QueryEscape(user), nil, &out)
	return out.Chain, err
}
