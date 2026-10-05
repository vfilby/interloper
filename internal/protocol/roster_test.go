package protocol_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vfilby/interloper/internal/protocol"
	"github.com/vfilby/interloper/internal/softdevice"
)

func TestRosterChain(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	a, _ := softdevice.New("phone A")
	b, _ := softdevice.New("phone B")
	c, _ := softdevice.New("phone C")
	cardB, _ := b.Card(now)
	cardC, _ := c.Card(now)

	r1, err := a.Genesis("vince", now)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := protocol.VerifyChain([]protocol.Envelope{r1}, "vince", "")
	if err != nil {
		t.Fatal(err)
	}
	pin := h1.Account
	if len(strings.Split(pin, "-")) != 8 {
		t.Fatalf("account fingerprint %q", pin)
	}
	r2, _ := a.Admit(h1, cardB, now) // A admits B
	h2, err := protocol.Extend(h1, r2)
	if err != nil {
		t.Fatal(err)
	}
	r3, _ := b.Admit(h2, cardC, now) // B, now a member, admits C
	h3, _ := protocol.Extend(h2, r3)
	r4, _ := c.Remove(h3, a.ID(), now) // C removes A
	chain := []protocol.Envelope{r1, r2, r3, r4}
	head, err := protocol.VerifyChain(chain, "vince", pin)
	if err != nil {
		t.Fatal(err)
	}
	if head.Roster.Seq != 4 || len(head.Devices) != 2 || head.Devices[a.ID()].DeviceID != "" {
		t.Fatalf("head %+v", head.Roster)
	}

	// A, removed in r4, can no longer sign the next roster.
	h4, _ := protocol.VerifyChain(chain, "vince", pin)
	mallory, _ := softdevice.New("mallory")
	cardM, _ := mallory.Card(now)
	afterRemoval, _ := a.Admit(h4, cardM, now)
	if _, err := protocol.Extend(h4, afterRemoval); err == nil {
		t.Fatal("a removed device signed the next roster")
	}

	cases := []struct {
		name  string
		chain func() []protocol.Envelope
		user  string
		pin   string
		want  string
	}{
		{"wrong pin", func() []protocol.Envelope { return chain }, "vince", "0000-0000-0000-0000-0000-0000-0000-0000", "does not match"},
		{"wrong user", func() []protocol.Envelope { return chain }, "kim", pin, "this user"},
		{"another genesis (hub swaps the account)", func() []protocol.Envelope {
			g, _ := mallory.Genesis("vince", now)
			return []protocol.Envelope{g}
		}, "vince", pin, "does not match"},
		{"new device signs its own admission", func() []protocol.Envelope {
			self, _ := mallory.Admit(h1, cardM, now)
			return []protocol.Envelope{r1, self}
		}, "vince", pin, "not a member"},
		{"skipped roster", func() []protocol.Envelope { return []protocol.Envelope{r1, r3} }, "vince", pin, "not a member"},
		{"replayed roster", func() []protocol.Envelope { return []protocol.Envelope{r1, r2, r2} }, "vince", pin, "seq"},
		{"wrong prev", func() []protocol.Envelope {
			r := protocol.NextRoster(h1, h1.Cards(), now.Unix())
			r.Prev = protocol.B64([]byte("nope"))
			e, _ := protocol.SignRoster(a.Approve, a.ID(), r)
			return []protocol.Envelope{r1, e}
		}, "vince", pin, "does not follow"},
		{"device listed twice", func() []protocol.Envelope {
			e, _ := a.Admit(h1, h1.Cards()[0], now)
			return []protocol.Envelope{r1, e}
		}, "vince", pin, "twice"},
		{"unknown member kind", func() []protocol.Envelope {
			r := protocol.NextRoster(h1, h1.Cards(), now.Unix())
			r.Members[0].Kind = "recovery"
			e, _ := protocol.SignRoster(a.Approve, a.ID(), r)
			return []protocol.Envelope{r1, e}
		}, "vince", pin, "unknown member kind"},
		{"tampered member card", func() []protocol.Envelope {
			r := protocol.NextRoster(h1, append(h1.Cards(), cardB), now.Unix())
			var cc protocol.DeviceCard
			p, _ := r.Members[1].Card.PayloadBytes()
			_ = json.Unmarshal(p, &cc)
			cc.EncKey = protocol.B64(mallory.Enc.PublicKey().Bytes()) // redirect B's requests to mallory
			b2, _ := json.Marshal(cc)
			r.Members[1].Card.Payload = protocol.B64(b2)
			e, _ := protocol.SignRoster(a.Approve, a.ID(), r)
			return []protocol.Envelope{r1, e}
		}, "vince", pin, "card"},
	}
	for _, c := range cases {
		_, err := protocol.VerifyChain(c.chain(), c.user, c.pin)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
}
