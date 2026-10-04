package apns

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSend(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var got *http.Request
	var body []byte
	status, reason := http.StatusOK, ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(status)
		if reason != "" {
			_ = json.NewEncoder(w).Encode(map[string]string{"reason": reason})
		}
	}))
	defer srv.Close()

	now := time.Unix(1_790_000_000, 0)
	c := &Client{KeyID: "ABC123DEFG", TeamID: "TEAM123456", Topic: "com.example.app", Key: key, Endpoint: srv.URL,
		Now: func() time.Time { return now }}
	exp := now.Add(15 * time.Minute)
	if err := c.Send(context.Background(), "a1b2c3", false, Notification{Title: "T", Body: "B", Expiration: exp}); err != nil {
		t.Fatal(err)
	}
	if got.URL.Path != "/3/device/a1b2c3" || got.Header.Get("apns-topic") != "com.example.app" ||
		got.Header.Get("apns-push-type") != "alert" || got.Header.Get("apns-expiration") != "1790000900" {
		t.Fatalf("request: %s %v", got.URL.Path, got.Header)
	}
	var payload struct {
		APS struct {
			Alert map[string]string `json:"alert"`
		} `json:"aps"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.APS.Alert["title"] != "T" || payload.APS.Alert["body"] != "B" {
		t.Fatalf("payload %s", body)
	}

	// The provider token is an ES256 JWT over {alg, kid}.{iss, iat}, verifiable with the key.
	jwt := strings.TrimPrefix(got.Header.Get("authorization"), "bearer ")
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt %q", jwt)
	}
	head, _ := base64.RawURLEncoding.DecodeString(parts[0])
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if string(head) != `{"alg":"ES256","kid":"ABC123DEFG"}` || string(claims) != `{"iat":1790000000,"iss":"TEAM123456"}` {
		t.Fatalf("jwt head %s claims %s", head, claims)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(&key.PublicKey, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("jwt signature does not verify")
	}

	// Reused within its life, renewed after.
	_ = c.Send(context.Background(), "a1b2c3", false, Notification{})
	if strings.TrimPrefix(got.Header.Get("authorization"), "bearer ") != jwt {
		t.Fatal("provider token not reused")
	}
	now = now.Add(tokenLife)
	_ = c.Send(context.Background(), "a1b2c3", false, Notification{})
	if strings.TrimPrefix(got.Header.Get("authorization"), "bearer ") == jwt {
		t.Fatal("provider token not renewed")
	}

	// A dead device token is reported as such; other failures are plain errors.
	status, reason = http.StatusGone, "Unregistered"
	if err := c.Send(context.Background(), "a1b2c3", false, Notification{}); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("410: %v", err)
	}
	status, reason = http.StatusBadRequest, "BadDeviceToken"
	if err := c.Send(context.Background(), "a1b2c3", false, Notification{}); !errors.Is(err, ErrUnregistered) {
		t.Fatalf("bad token: %v", err)
	}
	status, reason = http.StatusTooManyRequests, "TooManyRequests"
	if err := c.Send(context.Background(), "a1b2c3", false, Notification{}); err == nil || errors.Is(err, ErrUnregistered) {
		t.Fatalf("429: %v", err)
	}
}

func TestLoadKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	p := filepath.Join(t.TempDir(), "AuthKey_TEST.p8")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o400); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKey(p)
	if err != nil || !got.Equal(key) {
		t.Fatalf("LoadKey: %v", err)
	}
}
