// Package apns sends notifications through Apple's push service (APNs) with token authentication over HTTP/2.
//
// The hub only sends wake-ups: a fixed text, no request content, so Apple and anyone who reads the push learn only
// that something is waiting. The record itself stays sealed at the hub until the app fetches it.
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	Production = "https://api.push.apple.com"
	Sandbox    = "https://api.sandbox.push.apple.com"
	// Apple refuses provider tokens older than an hour and too-frequent new ones; 40 minutes sits between.
	tokenLife = 40 * time.Minute
)

// ErrUnregistered: the device token is no longer valid for this app (uninstalled, or a token from another
// environment). The sender should forget it.
var ErrUnregistered = errors.New("apns: device token no longer valid")

type Notification struct {
	Title, Body string
	Expiration  time.Time // APNs stops retrying after this; zero: one attempt only
	ThreadID    string    // groups notifications on the phone
}

type Client struct {
	KeyID, TeamID, Topic string
	Key                  *ecdsa.PrivateKey
	HTTP                 *http.Client // nil: a client with HTTP/2
	Now                  func() time.Time
	// Endpoint overrides both production and sandbox (tests).
	Endpoint string

	mu    sync.Mutex
	jwt   string
	jwtAt time.Time
}

// LoadKey reads the .p8 file App Store Connect / the developer portal gives for an APNs key (PKCS #8, P-256).
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("apns key: not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apns key: %w", err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apns key: not an EC key")
	}
	return ec, nil
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// providerToken is the ES256 JWT APNs authenticates the sender with, reused until it is tokenLife old.
func (c *Client) providerToken() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.jwt != "" && now.Sub(c.jwtAt) < tokenLife {
		return c.jwt, nil
	}
	enc := base64.RawURLEncoding
	head, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": c.KeyID})
	claims, _ := json.Marshal(map[string]any{"iss": c.TeamID, "iat": now.Unix()})
	signing := enc.EncodeToString(head) + "." + enc.EncodeToString(claims)
	h := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, c.Key, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	c.jwt, c.jwtAt = signing+"."+enc.EncodeToString(sig), now
	return c.jwt, nil
}

// Send pushes one alert to one device. sandbox selects Apple's development environment (Xcode debug builds);
// TestFlight and App Store builds use production.
func (c *Client) Send(ctx context.Context, deviceToken string, sandbox bool, n Notification) error {
	jwt, err := c.providerToken()
	if err != nil {
		return err
	}
	aps := map[string]any{"alert": map[string]string{"title": n.Title, "body": n.Body}, "sound": "default"}
	if n.ThreadID != "" {
		aps["thread-id"] = n.ThreadID
	}
	body, _ := json.Marshal(map[string]any{"aps": aps})

	base := Production
	if sandbox {
		base = Sandbox
	}
	if c.Endpoint != "" {
		base = c.Endpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+deviceToken, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("authorization", "bearer "+jwt)
	req.Header.Set("apns-topic", c.Topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	exp := int64(0)
	if !n.Expiration.IsZero() {
		exp = n.Expiration.Unix()
	}
	req.Header.Set("apns-expiration", strconv.FormatInt(exp, 10))

	hc := c.HTTP
	if hc == nil {
		hc = defaultHTTP
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var why struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&why)
	switch {
	case resp.StatusCode == http.StatusGone,
		why.Reason == "BadDeviceToken", why.Reason == "DeviceTokenNotForTopic", why.Reason == "Unregistered":
		return fmt.Errorf("%w (%d %s)", ErrUnregistered, resp.StatusCode, why.Reason)
	case why.Reason == "ExpiredProviderToken":
		c.mu.Lock()
		c.jwt = "" // the next send makes a fresh one
		c.mu.Unlock()
	}
	return fmt.Errorf("apns: %d %s", resp.StatusCode, why.Reason)
}

// APNs needs HTTP/2; the standard transport negotiates it over TLS.
var defaultHTTP = &http.Client{Timeout: 15 * time.Second, Transport: func() http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ForceAttemptHTTP2 = true
	return t
}()}
