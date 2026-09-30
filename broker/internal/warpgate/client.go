// Package warpgate is the small part of Warpgate's admin and user APIs the broker uses, as of Warpgate 0.28.6.
//
// The token belongs to the `approver` user, whose only admin role holds ticket_requests_manage. With it the broker
// can list and deny ticket requests, and read the user and target lists (0.28.6 lets any admin context read those),
// which it needs because a TicketRequest carries ids only.
package warpgate

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

// ErrNotPending: the request is gone or already resolved (Warpgate answers 404).
var ErrNotPending = errors.New("ticket request not found or no longer pending")

// ErrUnauthorized: the token was rejected (revoked, expired, or lost its admin role).
var ErrUnauthorized = errors.New("Warpgate rejected the approver token (revoked, expired, or no admin role)")

type TicketRequest struct {
	ID       string `json:"id"`
	UserID   string `json:"user_id"`
	TargetID string `json:"target_id"`
	// What Warpgate will grant: the requested duration, or the target's cap when none was asked for; null only
	// when neither exists, which means a ticket that never expires.
	RequestedDurationSeconds *int64    `json:"requested_duration_seconds"`
	Description              string    `json:"description"`
	Status                   string    `json:"status"`
	Created                  time.Time `json:"created"`
}

type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a client for base (e.g. https://bastion.home.example). hc may be nil.
func New(base, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	return &Client{base: strings.TrimRight(base, "/"), token: token, http: hc}
}

const maxBody = 4 << 20

func (c *Client) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-Warpgate-Token", c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("%s %s: reading body: %w", method, path, err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return resp.StatusCode, fmt.Errorf("%s %s: HTTP %d: %w", method, path, resp.StatusCode, ErrUnauthorized)
	case resp.StatusCode/100 != 2:
		return resp.StatusCode, fmt.Errorf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, snippet(data))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: decoding response: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// PendingRequests lists every Pending ticket request.
func (c *Client) PendingRequests(ctx context.Context) ([]TicketRequest, error) {
	var all []TicketRequest
	if _, err := c.do(ctx, http.MethodGet, "/@warpgate/admin/api/ticket-requests?status=Pending", nil, &all); err != nil {
		return nil, err
	}
	out := all[:0]
	for _, r := range all {
		if r.Status == "Pending" { // the filter is server-side; do not trust it blindly
			out = append(out, r)
		}
	}
	return out, nil
}

// Usernames maps user id to username.
func (c *Client) Usernames(ctx context.Context) (map[string]string, error) {
	var us []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/@warpgate/admin/api/users", nil, &us); err != nil {
		return nil, err
	}
	m := make(map[string]string, len(us))
	for _, u := range us {
		m[u.ID] = u.Username
	}
	return m, nil
}

// TargetNames maps target id to target name.
func (c *Client) TargetNames(ctx context.Context) (map[string]string, error) {
	var ts []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/@warpgate/admin/api/targets", nil, &ts); err != nil {
		return nil, err
	}
	m := make(map[string]string, len(ts))
	for _, t := range ts {
		m[t.ID] = t.Name
	}
	return m, nil
}

// Deny denies a pending request; the reason is shown to the requester (bastion-ssh prints it).
func (c *Client) Deny(ctx context.Context, id, reason string) error {
	code, err := c.do(ctx, http.MethodPost, "/@warpgate/admin/api/ticket-requests/"+url.PathEscape(id)+"/deny",
		map[string]string{"reason": reason}, nil)
	if code == http.StatusNotFound {
		return ErrNotPending
	}
	return err
}

// TokenExpiries lists the expiry of every API token of the approver user (normally exactly one).
func (c *Client) TokenExpiries(ctx context.Context) ([]time.Time, error) {
	var ts []struct {
		Expiry time.Time `json:"expiry"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/@warpgate/api/profile/api-tokens", nil, &ts); err != nil {
		return nil, err
	}
	out := make([]time.Time, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Expiry)
	}
	return out, nil
}
