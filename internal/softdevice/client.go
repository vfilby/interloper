package softdevice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vfilby/interpose/internal/protocol"
)

// Client is the device's side of the hub API, as the app implements it.
type Client struct {
	Base  string
	Token string
	HTTP  *http.Client
}

type HubAdapter struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
}

type HubRequest struct {
	ID        string          `json:"id"`
	Adapter   string          `json:"adapter"`
	Kind      string          `json:"kind"`
	CreatedAt int64           `json:"created_at"`
	ExpiresAt int64           `json:"expires_at"`
	Box       protocol.Sealed `json:"box"`
}

type HubAck struct {
	Adapter   string            `json:"adapter"`
	RequestID string            `json:"request_id"`
	Ack       protocol.Envelope `json:"ack"`
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, body)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("hub %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Enroll spends the one-time code and stores the device token in c.
type EnrollResult struct {
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`
	User     string `json:"user"`
	Status   string `json:"status"` // active | pending
}

// Enroll spends the one-time code and stores the device token in c. genesis is the new user's first roster for a
// `new` code, nil for a `join` code.
func (c *Client) Enroll(ctx context.Context, code string, card protocol.Envelope, genesis *protocol.Envelope) (EnrollResult, error) {
	var out EnrollResult
	in := map[string]any{"code": code, "card": card}
	if genesis != nil {
		in["genesis"] = genesis
	}
	if err := c.do(ctx, http.MethodPost, "/v1/enroll", in, &out); err != nil {
		return out, err
	}
	c.Token = out.Token
	return out, nil
}

// Roster fetches this device's user's chain (unverified).
func (c *Client) Roster(ctx context.Context) ([]protocol.Envelope, error) {
	var out struct {
		Chain []protocol.Envelope `json:"chain"`
	}
	return out.Chain, c.do(ctx, http.MethodGet, "/v1/device/roster", nil, &out)
}

func (c *Client) PostRoster(ctx context.Context, r protocol.Envelope) error {
	return c.do(ctx, http.MethodPost, "/v1/device/roster", map[string]any{"roster": r}, nil)
}

type Join struct {
	DeviceID    string            `json:"device_id"`
	Name        string            `json:"name"`
	Card        protocol.Envelope `json:"card"`
	RequestedAt int64             `json:"requested_at"`
}

func (c *Client) Joins(ctx context.Context) ([]Join, error) {
	var out []Join
	return out, c.do(ctx, http.MethodGet, "/v1/device/joins", nil, &out)
}

func (c *Client) Adapters(ctx context.Context) ([]HubAdapter, error) {
	var out []HubAdapter
	return out, c.do(ctx, http.MethodGet, "/v1/device/adapters", nil, &out)
}

func (c *Client) Requests(ctx context.Context) ([]HubRequest, error) {
	var out []HubRequest
	return out, c.do(ctx, http.MethodGet, "/v1/device/requests", nil, &out)
}

func (c *Client) Decide(ctx context.Context, adapter, requestID string, d protocol.Envelope) error {
	return c.do(ctx, http.MethodPost, "/v1/device/decisions",
		map[string]any{"adapter": adapter, "request_id": requestID, "decision": d}, nil)
}

func (c *Client) Acks(ctx context.Context, since int64) ([]HubAck, error) {
	var out []HubAck
	return out, c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/device/acks?since=%d", since), nil, &out)
}

// ReadAck verifies an ack against a pinned adapter key.
func ReadAck(e protocol.Envelope, adapterKey []byte) (protocol.Ack, error) {
	var a protocol.Ack
	p, err := protocol.VerifyEd25519(e, adapterKey)
	if err != nil {
		return a, err
	}
	if err := json.Unmarshal(p, &a); err != nil {
		return a, err
	}
	if a.Adapter != e.Kid {
		return a, fmt.Errorf("ack names adapter %q but is signed by %q", a.Adapter, e.Kid)
	}
	return a, nil
}
