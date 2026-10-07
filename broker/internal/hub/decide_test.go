package hub

import (
	"errors"
	"strings"
	"testing"

	"github.com/vfilby/interpose/internal/protocol"
	"github.com/vfilby/interpose/internal/softdevice"
)

// decision signs a decision as the hub would receive it (the hub never sees the record, so the hash is made up).
func decision(t *testing.T, d *softdevice.Device, adapter, requestID, verdict string, approveKey bool, ts int64) protocol.Envelope {
	t.Helper()
	k := d.Deny
	if approveKey {
		k = d.Approve
	}
	e, err := protocol.SignES256(k, d.ID(), protocol.Decision{V: protocol.Version, RequestID: requestID, Adapter: adapter,
		Decision: verdict, RecordHash: "h", Nonce: "n", DeviceID: d.ID(), TS: ts})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func publishFor(t *testing.T, acc account, adapter, id string) {
	t.Helper()
	box := protocol.Sealed{Suite: protocol.SuiteHPKE, Enc: "e", CT: "c"}
	r := Request{ID: id, Kind: "k", ExpiresAt: acc.now.Unix() + 600,
		Boxes: map[string]protocol.Sealed{acc.a.ID(): box, acc.b.ID(): box}}
	if _, err := acc.st.Publish(adapter, r, acc.now); err != nil {
		t.Fatal(err)
	}
}

func queuedFor(st *Store, adapter string) []QueuedDecision {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []QueuedDecision
	for _, q := range st.s.Decisions {
		if q.Adapter == adapter {
			out = append(out, q)
		}
	}
	return out
}

// The hub queues only decisions the device signed, for this adapter and request.
func TestDecideRefusesJunk(t *testing.T) {
	acc := newAccount(t, "vince")
	st, now := acc.st, acc.now
	publishFor(t, acc, "demo", "r1")
	publishFor(t, acc, "demo", "r2")

	tampered := decision(t, acc.a, "demo", "r1", protocol.Deny, false, now.Unix())
	p, _ := tampered.PayloadBytes()
	tampered.Payload = protocol.B64([]byte(strings.Replace(string(p), `"deny"`, `"approve"`, 1)))
	huge := decision(t, acc.a, "demo", "r1", protocol.Deny, false, now.Unix())
	huge.Sig += strings.Repeat("A", 100<<10)
	junk := protocol.Envelope{Alg: protocol.AlgES256, Kid: acc.a.ID(), Payload: protocol.B64([]byte("{}")), Sig: "AAAA"}

	for name, e := range map[string]protocol.Envelope{
		"junk":                       junk,
		"oversized":                  huge,
		"signed by the other phone":  decision(t, acc.b, "demo", "r1", protocol.Approve, true, now.Unix()),
		"payload edited":             tampered,
		"approve with the deny key":  decision(t, acc.a, "demo", "r1", protocol.Approve, false, now.Unix()),
		"for another request":        decision(t, acc.a, "demo", "r2", protocol.Approve, true, now.Unix()),
		"for another adapter":        decision(t, acc.a, "other", "r1", protocol.Approve, true, now.Unix()),
		"neither approve nor deny":   decision(t, acc.a, "demo", "r1", "maybe", true, now.Unix()),
		"signed with the wrong algo": {Alg: protocol.AlgEd25519, Kid: acc.a.ID(), Payload: junk.Payload, Sig: junk.Sig},
	} {
		if err := st.Decide(acc.a.ID(), "demo", "r1", e, now); !errors.Is(err, ErrBadDecision) {
			t.Errorf("%s: got %v, want ErrBadDecision", name, err)
		}
	}
	if q := queuedFor(st, "demo"); len(q) != 0 {
		t.Fatalf("junk queued: %+v", q)
	}

	for _, e := range []protocol.Envelope{
		decision(t, acc.a, "demo", "r1", protocol.Approve, true, now.Unix()),
		decision(t, acc.a, "demo", "r1", protocol.Deny, false, now.Unix()),
		decision(t, acc.a, "demo", "r1", protocol.Deny, true, now.Unix()), // deny may use the approve key
	} {
		if err := st.Decide(acc.a.ID(), "demo", "r1", e, now); err != nil {
			t.Fatalf("genuine decision refused: %v", err)
		}
	}
}

// A device has at most one decision queued per request; the newest one is kept.
func TestDecideReplacesPerDeviceAndRequest(t *testing.T) {
	acc := newAccount(t, "vince")
	st, now := acc.st, acc.now
	publishFor(t, acc, "demo", "r1")
	publishFor(t, acc, "demo", "r2")

	var last protocol.Envelope
	for i := range 50 {
		last = decision(t, acc.a, "demo", "r1", protocol.Approve, true, now.Unix()+int64(i))
		if err := st.Decide(acc.a.ID(), "demo", "r1", last, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Decide(acc.b.ID(), "demo", "r1", decision(t, acc.b, "demo", "r1", protocol.Deny, false, now.Unix()), now); err != nil {
		t.Fatal(err)
	}
	if err := st.Decide(acc.a.ID(), "demo", "r2", decision(t, acc.a, "demo", "r2", protocol.Deny, false, now.Unix()), now); err != nil {
		t.Fatal(err)
	}
	q := queuedFor(st, "demo")
	if len(q) != 3 {
		t.Fatalf("want 3 queued (one per device and request), got %d", len(q))
	}
	if q[0].DeviceID != acc.a.ID() || q[0].RequestID != "r1" || q[0].Decision != last {
		t.Fatalf("the newest decision did not replace the older ones: %+v", q[0])
	}

	// Once the adapter takes it, the device can decide again (after a rejected or failed note).
	if got := st.TakeDecisions("demo"); len(got) != 3 {
		t.Fatalf("took %d", len(got))
	}
	if err := st.Decide(acc.a.ID(), "demo", "r1", last, now); err != nil {
		t.Fatal(err)
	}
	if q := queuedFor(st, "demo"); len(q) != 1 {
		t.Fatalf("queued %d", len(q))
	}
}

// A full queue for one adapter does not stop decisions for another.
func TestDecideCapIsPerAdapter(t *testing.T) {
	acc := newAccount(t, "vince")
	st, now := acc.st, acc.now
	publishFor(t, acc, "busy", "r1")
	publishFor(t, acc, "busy", "r2")
	publishFor(t, acc, "quiet", "r1")

	// Two devices cannot fill a queue on their own any more (one decision per request, 200 pending requests), so fill
	// it directly, as many devices of many users would.
	if err := st.Decide(acc.a.ID(), "busy", "r1", decision(t, acc.a, "busy", "r1", protocol.Deny, false, now.Unix()), now); err != nil {
		t.Fatal(err)
	}
	st.mu.Lock()
	for range MaxDecisionsPerAdapter - 1 {
		st.s.Decisions = append(st.s.Decisions, QueuedDecision{Adapter: "busy", RequestID: "x", DeviceID: "y"})
	}
	st.mu.Unlock()

	err := st.Decide(acc.a.ID(), "busy", "r2", decision(t, acc.a, "busy", "r2", protocol.Deny, false, now.Unix()), now)
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("full adapter queue: got %v", err)
	}
	// Replacing a queued decision needs no room.
	if err := st.Decide(acc.a.ID(), "busy", "r1", decision(t, acc.a, "busy", "r1", protocol.Approve, true, now.Unix()), now); err != nil {
		t.Fatalf("replacing in a full queue: %v", err)
	}
	if err := st.Decide(acc.a.ID(), "quiet", "r1", decision(t, acc.a, "quiet", "r1", protocol.Approve, true, now.Unix()), now); err != nil {
		t.Fatalf("another adapter's queue: %v", err)
	}
}
