package hub

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vfilby/interpose/internal/protocol"
	"github.com/vfilby/interpose/internal/softdevice"
)

// A member device posting roster after roster, each full of self-made cards, must not make the hub's chain or its
// per-lookup work grow without bound.
func TestRosterBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a, _ := softdevice.New("phone A")
	cardA, _ := a.Card(now)
	genesis, _ := a.Genesis("vince", now)
	code, _, _ := st.NewEnrollCode(now, "vince", ModeNew)
	if _, err := st.Enroll(code, cardA, &genesis, now); err != nil {
		t.Fatal(err)
	}
	head := func() protocol.Head {
		t.Helper()
		chain, _ := st.Chain("vince")
		h, err := protocol.VerifyChain(chain, "vince", "")
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	cards := func(n int) []protocol.Envelope {
		out := []protocol.Envelope{cardA}
		for len(out) < n {
			d, _ := softdevice.New(strings.Repeat("x", MaxDeviceName))
			c, _ := d.Card(now)
			out = append(out, c)
		}
		return out
	}
	roster := func(members []protocol.Envelope) protocol.Envelope {
		e, _ := protocol.SignRoster(a.Approve, a.ID(), protocol.NextRoster(head(), members, now.Unix()))
		return e
	}
	mustFail := func(what string, err error, want string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: got %v, want an error containing %q", what, err, want)
		}
	}

	// The most members, with the longest names, fit within the size cap.
	full := roster(cards(MaxRosterMembers))
	if n := len(full.Payload) + len(full.Sig); n > MaxRosterBytes*3/4 {
		t.Fatalf("a roster of %d members is %d bytes: too close to the %d-byte cap", MaxRosterMembers, n, MaxRosterBytes)
	}
	if _, err := st.AppendRoster("vince", full); err != nil {
		t.Fatal(err)
	}
	_, err = st.AppendRoster("vince", roster(cards(MaxRosterMembers+1)))
	mustFail("one member too many", err, "at most")
	big := roster([]protocol.Envelope{cardA})
	big.Payload += strings.Repeat("A", MaxRosterBytes)
	_, err = st.AppendRoster("vince", big)
	mustFail("oversized roster", err, "larger than")
	_, err = st.Leave(a.ID(), &big, false)
	mustFail("oversized roster on leave", err, "larger than")
	code, _, _ = st.NewEnrollCode(now, "kim", ModeNew)
	k, _ := softdevice.New("kim's phone")
	cardK, _ := k.Card(now)
	bigGenesis, _ := k.Genesis("kim", now)
	bigGenesis.Payload += strings.Repeat("A", MaxRosterBytes)
	_, err = st.Enroll(code, cardK, &bigGenesis, now)
	mustFail("oversized genesis", err, "larger than")

	// The chain fills up, and then takes no more rosters.
	h := head()
	for i := 2; i < MaxRosters; i++ {
		e, _ := protocol.SignRoster(a.Approve, a.ID(), protocol.NextRoster(h, []protocol.Envelope{cardA}, now.Unix()))
		if h, err = st.AppendRoster("vince", e); err != nil {
			t.Fatalf("roster %d: %v", i+1, err)
		}
	}
	if h := head(); h.Roster.Seq != MaxRosters {
		t.Fatalf("head seq %d, want %d", h.Roster.Seq, MaxRosters)
	}
	_, err = st.AppendRoster("vince", roster([]protocol.Envelope{cardA}))
	mustFail("roster past the cap", err, "the most the hub keeps")

	// The kept head is the chain's, and so is the one verified afresh after a restart.
	want := head()
	for _, s := range []*Store{st, func() *Store { s, _ := Open(path); return s }()} {
		for _, u := range s.Users() {
			if u.ID == "vince" && string(u.Head.Payload) != string(want.Payload) {
				t.Fatalf("kept head is seq %d, chain head is seq %d", u.Head.Roster.Seq, want.Roster.Seq)
			}
		}
	}

	// A chain replaced behind the hub's back is verified again, not served from the kept head.
	st.ForceChain("vince", []protocol.Envelope{full})
	if u := st.Users(); len(u) != 1 || u[0].Head.Roster.Seq != 0 {
		t.Fatalf("a broken chain still has a head: %+v", u)
	}

	// A deleted account's head goes with it: a new account under the same name starts from its own genesis.
	if _, err := st.DeleteUser("vince"); err != nil {
		t.Fatal(err)
	}
	b, _ := softdevice.New("phone B")
	cardB, _ := b.Card(now)
	genesisB, _ := b.Genesis("vince", now)
	code, _, _ = st.NewEnrollCode(now, "vince", ModeNew)
	if _, err := st.Enroll(code, cardB, &genesisB, now); err != nil {
		t.Fatal(err)
	}
	if u := st.Users(); len(u) != 1 || u[0].Head.Roster.Seq != 1 || u[0].Head.Devices[b.ID()].DeviceID == "" {
		t.Fatalf("new account head %+v", u)
	}
}
