package protocol_test

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vfilby/interpose/internal/protocol"
	"github.com/vfilby/interpose/internal/softdevice"
)

type fixture struct {
	dev      *softdevice.Device
	card     protocol.DeviceCard
	adPub    ed25519.PublicKey
	adKey    ed25519.PrivateKey
	rec      protocol.Record
	now      time.Time
	opened   softdevice.Opened
	sentBody []byte
}

func setup(t *testing.T) *fixture {
	t.Helper()
	now := time.Unix(1_790_000_000, 0)
	dev, err := softdevice.New("test phone")
	if err != nil {
		t.Fatal(err)
	}
	ce, err := dev.Card(now)
	if err != nil {
		t.Fatal(err)
	}
	card, err := protocol.VerifyCard(ce)
	if err != nil {
		t.Fatal(err)
	}
	adPub, adKey, _ := ed25519.GenerateKey(nil)
	rec := protocol.Record{V: 1, ID: "r1", Adapter: "demo", Kind: "demo", Shape: protocol.ShapeOnce,
		Risk: protocol.RiskNormal, Title: "test", Requester: "claude", Facts: []protocol.Fact{{Label: "Host", Value: "x"}},
		Reason: "because", CreatedAt: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix(), Nonce: protocol.NewNonce()}
	signed, err := protocol.SignEd25519(adKey, "demo", rec)
	if err != nil {
		t.Fatal(err)
	}
	encKey, _ := protocol.UnB64(card.EncKey)
	box, err := protocol.Seal(nil, card.DeviceID, encKey, signed)
	if err != nil {
		t.Fatal(err)
	}
	o, err := dev.Read(box, adPub)
	if err != nil {
		t.Fatal(err)
	}
	sent, _ := signed.PayloadBytes()
	return &fixture{dev: dev, card: card, adPub: adPub, adKey: adKey, rec: rec, now: now, opened: o, sentBody: sent}
}

func TestRoundTrip(t *testing.T) {
	f := setup(t)
	if f.opened.Record.Nonce != f.rec.Nonce || string(f.opened.Payload) != string(f.sentBody) {
		t.Fatal("opened record differs from the one sealed")
	}
	for _, dec := range []string{protocol.Approve, protocol.Deny} {
		e, err := f.dev.Decide(f.opened, dec, f.now.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		d, err := protocol.VerifyDecision(e, f.card, "demo", f.sentBody, f.rec, f.now.Add(2*time.Minute))
		if err != nil {
			t.Fatalf("%s: %v", dec, err)
		}
		if d.Decision != dec {
			t.Fatalf("got %s", d.Decision)
		}
	}
}

func TestBoxForAnotherDeviceDoesNotOpen(t *testing.T) {
	f := setup(t)
	other, _ := softdevice.New("other")
	signed, _ := protocol.SignEd25519(f.adKey, "demo", f.rec)
	encKey, _ := protocol.UnB64(f.card.EncKey)
	box, _ := protocol.Seal(nil, f.card.DeviceID, encKey, signed)
	if _, err := other.Read(box, f.adPub); err == nil {
		t.Fatal("another device opened the box")
	}
}

func TestForgedRecordRejectedByDevice(t *testing.T) {
	f := setup(t)
	_, hubKey, _ := ed25519.GenerateKey(nil) // the hub (or anyone) signing a record of its own
	signed, _ := protocol.SignEd25519(hubKey, "demo", f.rec)
	encKey, _ := protocol.UnB64(f.card.EncKey)
	box, _ := protocol.Seal(nil, f.card.DeviceID, encKey, signed)
	if _, err := f.dev.Read(box, f.adPub); err == nil {
		t.Fatal("device accepted a record not signed by the pinned adapter key")
	}
}

func TestDecisionRejections(t *testing.T) {
	f := setup(t)
	mustDecide := func(dec string, ts time.Time) protocol.Envelope {
		e, err := f.dev.Decide(f.opened, dec, ts)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	other, _ := softdevice.New("other")
	otherOpened := f.opened
	otherApprove, _ := other.Decide(otherOpened, protocol.Approve, f.now)
	otherApprove.Kid = f.card.DeviceID // claims to be the pinned device

	// approve signed with the deny key
	denyKeyApprove := func() protocol.Envelope {
		d := protocol.Decision{V: 1, RequestID: "r1", Adapter: "demo", Decision: protocol.Approve,
			RecordHash: protocol.B64(protocol.Hash(f.sentBody)), Nonce: f.rec.Nonce, DeviceID: f.card.DeviceID, TS: f.now.Unix()}
		e, _ := protocol.SignES256(f.dev.Deny, f.card.DeviceID, d)
		return e
	}()

	otherRec := f.rec
	otherRec.Nonce = protocol.NewNonce()
	expired := f.rec
	expired.ExpiresAt = f.now.Unix() - 1

	cases := []struct {
		name    string
		env     protocol.Envelope
		adapter string
		body    []byte
		rec     protocol.Record
		now     time.Time
		want    string
	}{
		{"other device's key", otherApprove, "demo", f.sentBody, f.rec, f.now, "neither device key"},
		{"approve with deny key", denyKeyApprove, "demo", f.sentBody, f.rec, f.now, "approve key"},
		{"wrong adapter", mustDecide(protocol.Approve, f.now), "warpgate", f.sentBody, f.rec, f.now, "adapter"},
		{"different record bytes", mustDecide(protocol.Approve, f.now), "demo", append([]byte(" "), f.sentBody...), f.rec, f.now, "different record"},
		{"nonce mismatch", mustDecide(protocol.Approve, f.now), "demo", f.sentBody, otherRec, f.now, "nonce"},
		{"stale", mustDecide(protocol.Approve, f.now), "demo", f.sentBody, f.rec, f.now.Add(6 * time.Minute), "window"},
		{"expired", mustDecide(protocol.Approve, f.now), "demo", f.sentBody, expired, f.now, "expired"},
	}
	for _, c := range cases {
		_, err := protocol.VerifyDecision(c.env, f.card, c.adapter, c.body, c.rec, c.now)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
}

func TestCardTampering(t *testing.T) {
	f := setup(t)
	ce, _ := f.dev.Card(f.now)
	var c protocol.DeviceCard
	p, _ := ce.PayloadBytes()
	_ = json.Unmarshal(p, &c)
	other, _ := softdevice.New("other")
	oc, _ := other.Card(f.now)
	var o protocol.DeviceCard
	op, _ := oc.PayloadBytes()
	_ = json.Unmarshal(op, &o)
	c.EncKey = o.EncKey // swap in someone else's encryption key, keep the signature
	b, _ := json.Marshal(c)
	ce.Payload = protocol.B64(b)
	if _, err := protocol.VerifyCard(ce); err == nil {
		t.Fatal("tampered card verified")
	}
}

func TestFingerprint(t *testing.T) {
	fp := protocol.Fingerprint([]byte("abc"))
	if fp != "ba78-16bf-8f01-cfea" { // sha256("abc") = ba7816bf8f01cfea...
		t.Fatal(fp)
	}
}

func TestIDForms(t *testing.T) {
	d, _ := softdevice.New("phone")
	if id := d.ID(); !protocol.IsDeviceID(id) {
		t.Errorf("IsDeviceID(%q) = false", id)
	}
	if id := protocol.NewRequestID(); !protocol.IsRequestID(id) {
		t.Errorf("IsRequestID(%q) = false", id)
	}
	for _, s := range []string{"", "0123456789abcde", "0123456789abcdef0", "0123456789ABCDEF", "0123-56789abcdef", "0123456789abcdeg"} {
		if protocol.IsDeviceID(s) {
			t.Errorf("IsDeviceID(%q) = true", s)
		}
	}
	for _, s := range []string{"", "0123456789abcdef", "0123456789abcdef01234567x", "0123456789abcdef0123456Z", strings.Repeat("a", 4096)} {
		if protocol.IsRequestID(s) {
			t.Errorf("IsRequestID(%q) = true", s)
		}
	}
}
