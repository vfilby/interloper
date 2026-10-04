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

// world is a hub over real HTTP and one demo adapter that trusts user "vince", whose first device is "phone".
// "stranger" is the first device of user "kim", whom the adapter does not trust.
type world struct {
	t       *testing.T
	ctx     context.Context
	dir     string
	store   *hub.Store
	src     *demo.Source
	ad      *adapter.Adapter
	adHub   *adapter.HubClient
	adPub   ed25519.PublicKey
	srvURL  string
	account string

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

// enroll makes a device and enrolls it with a code for user/mode.
func (w *world) enroll(name, user, mode string) (*softdevice.Device, *softdevice.Client, softdevice.EnrollResult) {
	w.t.Helper()
	d, _ := softdevice.New(name)
	card, _ := d.Card(w.now)
	code, _, err := w.store.NewEnrollCode(time.Now(), user, mode)
	if err != nil {
		w.t.Fatal(err)
	}
	var genesis *protocol.Envelope
	if mode == hub.ModeNew {
		g, _ := d.Genesis(user, w.now)
		genesis = &g
	}
	c := &softdevice.Client{Base: w.srvURL}
	res, err := c.Enroll(w.ctx, code, card, genesis)
	if err != nil {
		w.t.Fatal(err)
	}
	return d, c, res
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	w := &world{t: t, ctx: context.Background(), dir: dir, now: time.Now()}
	st, err := hub.Open(filepath.Join(dir, "hub.json"))
	if err != nil {
		t.Fatal(err)
	}
	w.store = st
	srv := httptest.NewServer((&hub.API{Store: st, MaxWait: 200 * time.Millisecond}).Handler())
	t.Cleanup(srv.Close)
	w.srvURL = srv.URL

	pub, key, _ := ed25519.GenerateKey(nil)
	w.adPub = pub
	tok, err := st.AddAdapter("demo", protocol.B64(pub), w.now)
	if err != nil {
		t.Fatal(err)
	}
	w.adHub = &adapter.HubClient{Base: srv.URL, Token: tok}

	w.phone, w.phoneHub, _ = w.enroll("phone", "vince", hub.ModeNew)
	w.stranger, w.strHub, _ = w.enroll("stranger", "kim", hub.ModeNew)
	chain, _ := st.Chain("vince")
	h, err := protocol.VerifyChain(chain, "vince", "")
	if err != nil {
		t.Fatal(err)
	}
	w.account = h.Account // what the phone shows; the admin types it into trust add-user

	if err := adapter.TrustAddUser(dir, "vince", w.account); err != nil {
		t.Fatal(err)
	}
	trust, err := adapter.LoadTrust(dir)
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

func (w *world) pending(c *softdevice.Client) []softdevice.HubRequest {
	w.t.Helper()
	rs, err := c.Requests(w.ctx)
	if err != nil {
		w.t.Fatal(err)
	}
	return rs
}

func (w *world) head() protocol.Head {
	w.t.Helper()
	chain, err := w.phoneHub.Roster(w.ctx)
	if err != nil {
		w.t.Fatal(err)
	}
	h, err := protocol.VerifyChain(chain, "vince", w.account)
	if err != nil {
		w.t.Fatal(err)
	}
	return h
}

func (w *world) decide(d *softdevice.Device, o softdevice.Opened, dec string) {
	w.t.Helper()
	e, _ := d.Decide(o, dec, w.clock())
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: e.Kid, Decision: e})
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

// openOne adds a demo request, publishes it, and opens it on d.
func (w *world) openOne(d *softdevice.Device, c *softdevice.Client, title string) (adapter.Item, softdevice.Opened) {
	w.t.Helper()
	it := w.src.Add(adapter.Item{Requester: "claude", Title: title})
	w.tick()
	for _, r := range w.pending(c) {
		o, err := d.Read(r.Box, w.adPub)
		if err == nil && o.Record.Title == title {
			return it, o
		}
	}
	w.t.Fatalf("%q not delivered", title)
	return it, softdevice.Opened{}
}

func TestApproveEndToEnd(t *testing.T) {
	w := newWorld(t)
	it := w.src.Add(adapter.Item{Requester: "claude", Title: "claude wants RW on forge-01", Risk: protocol.RiskElevated,
		Reason: "fix the backups", Facts: []protocol.Fact{{Label: "Host", Value: "forge-01"}}})
	w.tick()

	if n := len(w.pending(w.strHub)); n != 0 {
		t.Fatalf("a device of a user the adapter does not trust got %d boxes", n)
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
	ds, err := w.adHub.Decisions(w.ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		w.ad.Handle(w.ctx, d)
	}

	if w.outcome(it.Key) != "resolved" {
		t.Fatal("the service was not acted on")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeApproved || !strings.Contains(a.Detail, "vince") {
		t.Fatalf("ack %+v", a)
	}
	if n := len(w.pending(w.phoneHub)); n != 0 {
		t.Fatalf("resolved request still offered (%d)", n)
	}
	// Replaying the same decision does nothing: the record is gone, its nonce with it.
	if err := w.phoneHub.Decide(w.ctx, "demo", o.Record.ID, dec); err == nil {
		t.Fatal("hub accepted a decision for a resolved request")
	}
}

// The hub (or anything that gets onto it) forges approvals: none of them may act.
func TestForgedDecisionsDoNothing(t *testing.T) {
	w := newWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "maggy wants ADMIN on n")

	// 1. A device of another user (enrolled at the hub, not trusted by the adapter), signing the real record.
	strDec, _ := w.stranger.Decide(o, protocol.Approve, w.clock())
	// 2. A deny signed by the phone, with the payload edited to "approve".
	deny, _ := w.phone.Decide(o, protocol.Deny, w.clock())
	p, _ := deny.PayloadBytes()
	deny.Payload = protocol.B64([]byte(strings.Replace(string(p), `"deny"`, `"approve"`, 1)))
	// 3. A genuine phone approval of a different record.
	_, oo := w.openOne(w.phone, w.phoneHub, "harmless")
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
	w.decide(w.phone, o, protocol.Deny) // the person can still decide
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeDenied {
		t.Fatalf("ack %+v", a)
	}
}

func TestChangedRequestIsResent(t *testing.T) {
	w := newWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "first wording")
	w.src.Mutate(it.Key, func(i *adapter.Item) { i.Title = "second wording" })
	w.decide(w.phone, o, protocol.Approve)
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
}

func TestUnansweredIsDenied(t *testing.T) {
	w := newWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "x")
	w.advance(16 * time.Minute)
	w.tick()
	if w.outcome(it.Key) != "resolved" {
		t.Fatal("expired request not denied at the service")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeExpired {
		t.Fatalf("ack %+v", a)
	}
}

func TestStaleDecisionRejected(t *testing.T) {
	w := newWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "x")
	dec, _ := w.phone.Decide(o, protocol.Approve, w.clock())
	w.advance(6 * time.Minute) // held back by the transport for longer than the window
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: dec.Kid, Decision: dec})
	if w.outcome(it.Key) != "pending" {
		t.Fatal("acted on a stale decision")
	}
}

func TestUntrustedUserAtAdapterStopsDecisions(t *testing.T) {
	w := newWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "x")
	time.Sleep(10 * time.Millisecond) // distinct mtime
	if err := adapter.TrustRemoveUser(w.dir, "vince"); err != nil {
		t.Fatal(err)
	}
	w.tick()
	w.decide(w.phone, o, protocol.Approve)
	if w.outcome(it.Key) != "pending" {
		t.Fatal("a device of a user the adapter no longer trusts acted")
	}
}

// A second phone joins vince: nothing reaches it until a phone already on the roster admits it.
func TestJoinApprovedOnExistingPhone(t *testing.T) {
	w := newWorld(t)
	phone2, hub2, res := w.enroll("phone 2", "vince", hub.ModeJoin)
	if res.Status != "pending" {
		t.Fatalf("join status %q", res.Status)
	}
	_, _ = w.openOne(w.phone, w.phoneHub, "before admission")
	if n := len(w.pending(hub2)); n != 0 {
		t.Fatalf("a device waiting for approval got %d boxes", n)
	}

	// A device cannot admit itself: the hub refuses, and so would every adapter.
	self, _ := phone2.Admit(w.head(), mustCard(t, phone2), w.now)
	if err := hub2.PostRoster(w.ctx, self); err == nil {
		t.Fatal("hub accepted a self-admission")
	}

	joins, err := w.phoneHub.Joins(w.ctx)
	if err != nil || len(joins) != 1 || joins[0].DeviceID != phone2.ID() {
		t.Fatalf("joins %+v %v", joins, err)
	}
	next, _ := w.phone.Admit(w.head(), joins[0].Card, w.now)
	if err := w.phoneHub.PostRoster(w.ctx, next); err != nil {
		t.Fatal(err)
	}

	it, o := w.openOne(phone2, hub2, "after admission")
	w.decide(phone2, o, protocol.Approve)
	if w.outcome(it.Key) != "resolved" {
		t.Fatal("admitted phone could not approve")
	}
	if a := w.lastAck(o.Record.ID); !strings.Contains(a.Detail, "vince on phone 2") {
		t.Fatalf("ack %+v", a)
	}
}

// Phone 2 is removed by phone 1. Its decisions stop counting at the adapter, and the hub stops serving it.
func TestRemovedPhoneCannotDecide(t *testing.T) {
	w := newWorld(t)
	phone2, hub2 := w.admitSecond()
	it, o := w.openOne(phone2, hub2, "sealed to both")

	rm, _ := w.phone.Remove(w.head(), phone2.ID(), w.now)
	if err := w.phoneHub.PostRoster(w.ctx, rm); err != nil {
		t.Fatal(err)
	}
	w.tick() // the adapter picks up the new roster
	w.decide(phone2, o, protocol.Approve)
	if w.outcome(it.Key) != "pending" {
		t.Fatal("a removed phone's decision acted")
	}
	if _, err := hub2.Requests(w.ctx); err == nil {
		t.Fatal("the hub still serves a removed phone")
	}
}

// The hub turns hostile after phone 2's removal: it serves the old roster, a forked one, or another account.
func TestHostileHubRosters(t *testing.T) {
	w := newWorld(t)
	phone2, _ := w.admitSecond()
	before, _ := w.store.Chain("vince") // v2: phone + phone 2
	h2 := w.head()
	rm, _ := w.phone.Remove(h2, phone2.ID(), w.now)
	if err := w.phoneHub.PostRoster(w.ctx, rm); err != nil {
		t.Fatal(err)
	}
	w.tick() // adapter now at v3: phone only

	mallory, _ := softdevice.New("mallory")
	mCard := mustCard(t, mallory)
	forkV3, _ := phone2.Admit(h2, mCard, w.now) // phone 2 was still on v2, so it can sign an alternative v3
	hFork, err := protocol.Extend(h2, forkV3)
	if err != nil {
		t.Fatal(err)
	}
	forkV4, _ := mallory.Admit(hFork, mustCard(t, phone2), w.now)
	other, _ := mallory.Genesis("vince", w.now)

	for name, chain := range map[string][]protocol.Envelope{
		"rollback to v2":              before,
		"fork from v2 (v3', v4')":     append(append([]protocol.Envelope{}, before...), forkV3, forkV4),
		"another account named vince": {other},
	} {
		w.store.ForceChain("vince", chain)
		w.tick()
		_, o := w.openOne(w.phone, w.phoneHub, "after: "+name)
		for _, d := range []*softdevice.Device{phone2, mallory} {
			e, _ := d.Decide(o, protocol.Approve, w.clock())
			w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: e.Kid, Decision: e})
		}
		if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeRejected {
			t.Errorf("%s: a removed or injected device's decision was not rejected: %+v", name, a)
		}
		// And the record was sealed to the phone only.
		if n := len(w.pending(w.phoneHub)); n == 0 {
			t.Errorf("%s: the legitimate phone lost its requests", name)
		}
	}
}

// admitSecond enrolls "phone 2" for vince and admits it from the first phone.
func (w *world) admitSecond() (*softdevice.Device, *softdevice.Client) {
	w.t.Helper()
	phone2, hub2, _ := w.enroll("phone 2", "vince", hub.ModeJoin)
	next, _ := w.phone.Admit(w.head(), mustCard(w.t, phone2), w.now)
	if err := w.phoneHub.PostRoster(w.ctx, next); err != nil {
		w.t.Fatal(err)
	}
	w.tick()
	return phone2, hub2
}

func mustCard(t *testing.T, d *softdevice.Device) protocol.Envelope {
	t.Helper()
	c, err := d.Card(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}
