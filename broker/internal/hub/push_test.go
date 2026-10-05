package hub

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vfilby/interloper/broker/internal/apns"
	"github.com/vfilby/interloper/internal/protocol"
	"github.com/vfilby/interloper/internal/softdevice"
)

type fakePusher struct {
	mu   sync.Mutex
	sent []string // "token title"
	dead map[string]bool
}

func (f *fakePusher) Send(_ context.Context, token string, _ bool, n apns.Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, token+" "+n.Title)
	if f.dead[token] {
		return apns.ErrUnregistered
	}
	return nil
}

func (f *fakePusher) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.sent
	f.sent = nil
	return out
}

// Pushes carry no request content and go only to the devices a request was sealed for; dead tokens are forgotten.
func TestPushWakeUps(t *testing.T) {
	acc := newAccount(t, "vince")
	push := &fakePusher{dead: map[string]bool{}}
	api := &API{Store: acc.st, Push: push, pushed: make(chan struct{}, 4)}
	h := api.Handler()
	call := func(path, tok string, body any) int {
		t.Helper()
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	wait := func() {
		t.Helper()
		select {
		case <-api.pushed:
		case <-time.After(5 * time.Second):
			t.Fatal("no push")
		}
	}

	tokA, tokB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if code := call("/v1/device/push", acc.tokA, map[string]string{"token": "NOT-HEX", "environment": "production"}); code != http.StatusBadRequest {
		t.Fatalf("bad token accepted: %d", code)
	}
	if code := call("/v1/device/push", acc.tokA, map[string]string{"token": tokA, "environment": "staging"}); code != http.StatusBadRequest {
		t.Fatalf("bad environment accepted: %d", code)
	}
	for tok, dev := range map[string]string{acc.tokA: tokA, acc.tokB: tokB} {
		if code := call("/v1/device/push", tok, map[string]string{"token": dev, "environment": "production"}); code != http.StatusNoContent {
			t.Fatalf("register: %d", code)
		}
	}

	// An adapter publishes a request sealed for A only: only A is woken.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	adTok, err := acc.st.AddAdapter("demo", protocol.B64(pub), acc.now)
	if err != nil {
		t.Fatal(err)
	}
	box := protocol.Sealed{Suite: "hpke-p256-sha256-aes256gcm", Kid: acc.a.ID(), Enc: "x", CT: "y"}
	if code := call("/v1/adapter/requests", adTok, map[string]any{"id": "r1", "kind": "demo", "expires_at": acc.now.Add(time.Hour).Unix(),
		"boxes": map[string]protocol.Sealed{acc.a.ID(): box}}); code != http.StatusCreated {
		t.Fatalf("publish: %d", code)
	}
	wait()
	if got := push.take(); len(got) != 1 || got[0] != tokA+" Approval request" {
		t.Fatalf("pushed %v", got)
	}

	// A new phone asks to join: the account's phones are woken. B's token is dead by now and is forgotten.
	push.dead[tokB] = true
	c, _ := softdevice.New("phone C")
	cardC, _ := c.Card(acc.now)
	code, _, _ := acc.st.NewEnrollCode(acc.now, "vince", ModeJoin)
	b, _ := json.Marshal(map[string]any{"code": code, "card": cardC})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/enroll", bytes.NewReader(b)))
	if rec.Code != http.StatusOK {
		t.Fatalf("join: %d %s", rec.Code, rec.Body)
	}
	wait()
	if got := push.take(); len(got) != 2 {
		t.Fatalf("join pushed %v", got)
	}
	if d, _ := acc.st.Device(acc.b.ID()); d.PushToken != "" {
		t.Fatal("dead token kept")
	}
	if d, _ := acc.st.Device(acc.a.ID()); d.PushToken != tokA {
		t.Fatal("live token dropped")
	}
}
