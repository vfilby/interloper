package hub

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vfilby/interloper/internal/protocol"
	"github.com/vfilby/interloper/internal/softdevice"
)

func TestEnrollmentRules(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a, _ := softdevice.New("phone A")
	cardA, _ := a.Card(now)
	genesis, _ := a.Genesis("vince", now)
	enroll := func(user, mode string, card protocol.Envelope, g *protocol.Envelope) (Enrolled, error) {
		t.Helper()
		code, _, err := st.NewEnrollCode(now, user, mode)
		if err != nil {
			return Enrolled{}, err
		}
		return st.Enroll(code, card, g, now)
	}
	mustFail := func(what string, err error, want string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: got %v, want an error containing %q", what, err, want)
		}
	}

	_, err = enroll("vince", ModeJoin, cardA, nil)
	mustFail("join before the user exists", err, "no user vince")
	_, err = enroll("vince", ModeNew, cardA, nil)
	mustFail("new without genesis", err, "genesis")
	b, _ := softdevice.New("phone B")
	otherGenesis, _ := b.Genesis("vince", now)
	_, err = enroll("vince", ModeNew, cardA, &otherGenesis)
	mustFail("genesis of another device", err, "must contain and be signed by")

	first, err := enroll("vince", ModeNew, cardA, &genesis)
	if err != nil || !first.Active {
		t.Fatalf("new user: %+v %v", first, err)
	}
	_, _, err = st.NewEnrollCode(now, "vince", ModeNew)
	mustFail("second new code for an existing user", err, "exists")

	// Phone A leaves this hub and comes back with a join code: it is on the roster, so it is active at once, and the
	// old token stops working.
	again, err := enroll("vince", ModeJoin, cardA, nil)
	if err != nil || !again.Active {
		t.Fatalf("re-enroll: %+v %v", again, err)
	}
	if _, ok := st.DeviceByToken(first.Token, now); ok {
		t.Fatal("the old token still works after re-enrolling")
	}
	if _, ok := st.DeviceByToken(again.Token, now); !ok {
		t.Fatal("the new token does not work")
	}

	// Phone B joins: pending, listed as a join request, until A admits it.
	cardB, _ := b.Card(now)
	join, err := enroll("vince", ModeJoin, cardB, nil)
	if err != nil || join.Active {
		t.Fatalf("join: %+v %v", join, err)
	}
	if js := st.Joins("vince"); len(js) != 1 || js[0].ID != b.ID() {
		t.Fatalf("joins %+v", js)
	}
	chain, _ := st.Chain("vince")
	head, _ := protocol.VerifyChain(chain, "vince", "")
	self, _ := b.Admit(head, cardB, now)
	_, err = st.AppendRoster("vince", self)
	mustFail("self-admission", err, "not a member")
	next, _ := a.Admit(head, cardB, now)
	if _, err := st.AppendRoster("vince", next); err != nil {
		t.Fatal(err)
	}
	if js := st.Joins("vince"); len(js) != 0 {
		t.Fatalf("admitted device still a join request: %+v", js)
	}

	// A device of vince cannot enroll as kim.
	_, err = enroll("kim", ModeNew, cardB, func() *protocol.Envelope { g, _ := b.Genesis("kim", now); return &g }())
	mustFail("device of another user", err, "belongs to user vince")

	// A removes B: B's token stops working.
	chain, _ = st.Chain("vince")
	head, _ = protocol.VerifyChain(chain, "vince", "")
	rm, _ := a.Remove(head, b.ID(), now)
	if _, err := st.AppendRoster("vince", rm); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.DeviceByToken(join.Token, now); ok {
		t.Fatal("a removed device is still served")
	}

	// A code is single-use.
	code, _, _ := st.NewEnrollCode(now, "vince", ModeJoin)
	if _, err := st.Enroll(code, cardA, nil, now); err != nil {
		t.Fatal(err)
	}
	_, err = st.Enroll(code, cardA, nil, now)
	mustFail("spent code", err, "unknown, used or expired")
}
