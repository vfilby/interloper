package adapter_test

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"warpgate-approver/broker/internal/adapter"
	"warpgate-approver/broker/internal/adapter/demo"
	"warpgate-approver/broker/internal/hub"
	"warpgate-approver/broker/internal/protocol"
	"warpgate-approver/broker/internal/softdevice"
)

// world is a hub over real HTTP, one demo adapter and two software devices: "phone" (trusted by the adapter) and
// "stranger" (enrolled at the hub only).
type world struct {
	t        *testing.T
	ctx      context.Context
	store    *hub.Store
	src      *demo.Source
	ad       *adapter.Adapter
	adHub    *adapter.HubClient
	adPub    ed25519.PublicKey
	phone    *softdevice.Device
	phoneHub *softdevice.Client
	stranger *softdevice.Device
	strHub   *softdevice.Client

	mu  sync.Mutex
	now time.Time
}

func (w *world) clock() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.now
}

func (w *world) advance(d time.Duration) {
	w.mu.Lock()
	w.now = w.now.Add(d)
	w.mu.Unlock()
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	w := &world{t: t, ctx: context.Background(), now: time.Now()}
	st, err := hub.Open(filepath.Join(dir, "hub.json"))
	if err != nil {
		t.Fatal(err)
	}
	w.store = st
	srv := httptest.NewServer((&hub.API{Store: st, MaxWait: 200 * time.Millisecond}).Handler())
	t.Cleanup(srv.Close)

	pub, key, _ := ed25519.GenerateKey(nil)
	w.adPub = pub
	tok, err := st.AddAdapter("demo", protocol.B64(pub), w.now)
	if err != nil {
		t.Fatal(err)
	}
	w.adHub = &adapter.HubClient{Base: srv.URL, Token: tok}

	enroll := func(name string) (*softdevice.Device, *softdevice.Client, protocol.Envelope) {
		d, _ := softdevice.New(name)
		card, _ := d.Card(w.now)
		code, err := st.NewEnrollCode(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		c := &softdevice.Client{Base: srv.URL}
		if _, err := c.Enroll(w.ctx, code, card); err != nil {
			t.Fatal(err)
		}
		return d, c, card
	}
	var phoneCard protocol.Envelope
	w.phone, w.phoneHub, phoneCard = enroll("phone")
	w.stranger, w.strHub, _ = enroll("stranger")

	trustPath := filepath.Join(dir, "trusted-devices.json")
	if _, err := adapter.TrustAdd(trustPath, phoneCard); err != nil {
		t.Fatal(err)
	}
	trust, err := adapter.LoadTrust(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	w.src = demo.New()
	w.ad, err = adapter.New(adapter.Config{ID: "demo", Key: key, StateFile: filepath.Join(dir, "adapter.json"),
		TTL: 15 * time.Minute, Poll: time.Hour, Now: w.clock}, w.src, w.adHub, trust, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) tick() {
	w.t.Helper()
	if err := w.ad.Tick(w.ctx); err != nil {
		w.t.Fatal(err)
	}
}

// deliver hands every queued decision to the adapter, as its long-poll loop would.
func (w *world) deliver() {
	w.t.Helper()
	ds, err := w.adHub.Decisions(w.ctx, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, d := range ds {
		w.ad.Handle(w.ctx, d)
	}
}

func (w *world) pending(c *softdevice.Client) []softdevice.HubRequest {
	w.t.Helper()
	rs, err := c.Requests(w.ctx)
	if err != nil {
		w.t.Fatal(err)
	}
	return rs
}

func (w *world) lastAck(id string) protocol.Ack {
	w.t.Helper()
	acks, err := w.phoneHub.Acks(w.ctx, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	var out protocol.Ack
	found := false
	for _, a := range acks {
		if a.RequestID != id {
			continue
		}
		ack, err := softdevice.ReadAck(a.Ack, w.adPub)
		if err != nil {
			w.t.Fatalf("ack does not verify: %v", err)
		}
		out, found = ack, true
	}
	if !found {
		w.t.Fatalf("no ack for %s", id)
	}
	return out
}

func (w *world) outcome(key string) string {
	_, ok, _ := w.src.Current(w.ctx, key)
	if ok {
		return "pending"
	}
	return "resolved"
}

func TestApproveEndToEnd(t *testing.T) {
	w := newWorld(t)
	it := w.src.Add(adapter.Item{Requester: "claude", Title: "claude wants RW on build-01", Risk: protocol.RiskElevated,
		Reason: "fix the backups", Facts: []protocol.Fact{{Label: "Host", Value: "build-01"}}})
	w.tick()

	if n := len(w.pending(w.strHub)); n != 0 {
		t.Fatalf("a device the adapter does not trust got %d boxes", n)
	}
	rs := w.pending(w.phoneHub)
	if len(rs) != 1 {
		t.Fatalf("phone sees %d requests", len(rs))
	}
	o, err := w.phone.Read(rs[0].Box, w.adPub)
	if err != nil {
		t.Fatal(err)
	}
	if o.Record.Title != it.Title || o.Record.Reason != "fix the backups" {
		t.Fatalf("record %+v", o.Record)
	}
	dec, _ := w.phone.Decide(o, protocol.Approve, w.clock())
	if err := w.phoneHub.Decide(w.ctx, "demo", o.Record.ID, dec); err != nil {
		t.Fatal(err)
	}
	w.deliver()

	if w.outcome(it.Key) != "resolved" {
		t.Fatal("the service was not acted on")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeApproved {
		t.Fatalf("ack %+v", a)
	}
	if n := len(w.pending(w.phoneHub)); n != 0 {
		t.Fatalf("resolved request still offered (%d)", n)
	}

	// Replaying the same decision does nothing: the record is gone, its nonce with it.
	if err := w.phoneHub.Decide(w.ctx, "demo", o.Record.ID, dec); err == nil {
		t.Fatal("hub accepted a decision for a resolved request")
	}
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: w.phone.ID(), Decision: dec})
}

// The hub (or anything that gets onto it) forges approvals: none of them may act.
func TestForgedDecisionsDoNothing(t *testing.T) {
	w := newWorld(t)
	it := w.src.Add(adapter.Item{Requester: "helper", Title: "helper wants ADMIN on n", Risk: protocol.RiskHigh})
	w.tick()
	rs := w.pending(w.phoneHub)
	o, _ := w.phone.Read(rs[0].Box, w.adPub)

	// 1. A device the hub enrolled but the adapter never trusted, signing a perfect decision on the real record.
	strDec, _ := w.stranger.Decide(o, protocol.Approve, w.clock())
	// 2. The phone's own deny-key signature relabelled as an approval is impossible to build without the key; the
	//    closest is a deny signed by the phone, with the payload edited to "approve".
	deny, _ := w.phone.Decide(o, protocol.Deny, w.clock())
	p, _ := deny.PayloadBytes()
	deny.Payload = protocol.B64([]byte(strings.Replace(string(p), `"deny"`, `"approve"`, 1)))
	// 3. A genuine phone approval of a different record (another request's nonce and hash).
	other := w.src.Add(adapter.Item{Requester: "helper", Title: "harmless"})
	w.tick()
	var oo softdevice.Opened
	for _, r := range w.pending(w.phoneHub) {
		if r.ID != o.Record.ID {
			oo, _ = w.phone.Read(r.Box, w.adPub)
		}
	}
	swapped, _ := w.phone.Decide(oo, protocol.Approve, w.clock())

	for _, d := range []protocol.Envelope{strDec, deny, swapped} {
		w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: d.Kid, Decision: d})
	}
	if w.outcome(it.Key) != "pending" {
		t.Fatal("a forged decision acted on the service")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeRejected {
		t.Fatalf("want a rejected note, got %+v", a)
	}
	if n := len(w.pending(w.phoneHub)); n != 2 {
		t.Fatalf("rejected decisions must leave the request pending; phone sees %d", n)
	}
	_ = other

	// The person can still decide after the rejections.
	dec, _ := w.phone.Decide(o, protocol.Deny, w.clock())
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: dec.Kid, Decision: dec})
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeDenied {
		t.Fatalf("ack %+v", a)
	}
}

func TestChangedRequestIsResent(t *testing.T) {
	w := newWorld(t)
	it := w.src.Add(adapter.Item{Requester: "claude", Title: "first wording"})
	w.tick()
	o, _ := w.phone.Read(w.pending(w.phoneHub)[0].Box, w.adPub)

	// The service-side request changes after the person saw it (e.g. a longer duration).
	w.src.Mutate(it.Key, func(i *adapter.Item) { i.Title = "second wording" })
	dec, _ := w.phone.Decide(o, protocol.Approve, w.clock())
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: dec.Kid, Decision: dec})
	if w.outcome(it.Key) != "pending" {
		t.Fatal("approved a request that changed after it was shown")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeExpired || !strings.Contains(a.Detail, "changed") {
		t.Fatalf("ack %+v", a)
	}
	w.tick()
	rs := w.pending(w.phoneHub)
	if len(rs) != 1 || rs[0].ID == o.Record.ID {
		t.Fatalf("want one fresh record, got %+v", rs)
	}
	o2, _ := w.phone.Read(rs[0].Box, w.adPub)
	if o2.Record.Title != "second wording" {
		t.Fatal(o2.Record.Title)
	}
}

func TestUnansweredIsDenied(t *testing.T) {
	w := newWorld(t)
	it := w.src.Add(adapter.Item{Requester: "claude", Title: "x"})
	w.tick()
	id := w.pending(w.phoneHub)[0].ID
	w.advance(16 * time.Minute)
	w.tick()
	if w.outcome(it.Key) != "resolved" {
		t.Fatal("expired request not denied at the service")
	}
	if a := w.lastAck(id); a.Outcome != protocol.OutcomeExpired {
		t.Fatalf("ack %+v", a)
	}
}

func TestStaleDecisionRejected(t *testing.T) {
	w := newWorld(t)
	it := w.src.Add(adapter.Item{Requester: "claude", Title: "x"})
	w.tick()
	o, _ := w.phone.Read(w.pending(w.phoneHub)[0].Box, w.adPub)
	dec, _ := w.phone.Decide(o, protocol.Approve, w.clock())
	w.advance(6 * time.Minute) // held back by the transport for longer than the window
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: dec.Kid, Decision: dec})
	if w.outcome(it.Key) != "pending" {
		t.Fatal("acted on a stale decision")
	}
}

func TestRevokedAtAdapterStopsDecisions(t *testing.T) {
	w := newWorld(t)
	it := w.src.Add(adapter.Item{Requester: "claude", Title: "x"})
	w.tick()
	o, _ := w.phone.Read(w.pending(w.phoneHub)[0].Box, w.adPub)
	dec, _ := w.phone.Decide(o, protocol.Approve, w.clock())

	// Admin removes the phone from this adapter's trust list (lost phone). The file is reread on the next tick.
	time.Sleep(10 * time.Millisecond) // distinct mtime
	path := filepath.Join(filepath.Dir(w.store.Path()), "trusted-devices.json")
	if err := adapter.TrustRemove(path, w.phone.ID()); err != nil {
		t.Fatal(err)
	}
	w.tick()
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: dec.Kid, Decision: dec})
	if w.outcome(it.Key) != "pending" {
		t.Fatal("a removed device's decision acted")
	}
}
