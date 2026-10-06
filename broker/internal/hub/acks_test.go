package hub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/vfilby/interpose/internal/protocol"
	"github.com/vfilby/interpose/internal/softdevice"
)

// A device reads the outcomes of the requests sealed for it, not those of other accounts or other phones.
func TestAcksOnlyForRecipients(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	vince := addAccount(t, st, "vince", now)
	kim := addAccount(t, st, "kim", now)
	// A phone that asked to join kim's account and was not admitted.
	c, _ := softdevice.New("phone C")
	cardC, _ := c.Card(now)
	code, _, _ := st.NewEnrollCode(now, "kim", ModeJoin)
	join, err := st.Enroll(code, cardC, nil, now)
	if err != nil || join.Active {
		t.Fatalf("join: %+v %v", join, err)
	}

	box := func(id string) protocol.Sealed {
		return protocol.Sealed{Suite: "hpke-p256-sha256-aes256gcm", Kid: id, Enc: "x", CT: "y"}
	}
	publish := func(adapter, id string, to ...string) {
		t.Helper()
		boxes := map[string]protocol.Sealed{}
		for _, d := range to {
			boxes[d] = box(d)
		}
		r := Request{ID: id, Kind: "demo", CreatedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(), Boxes: boxes}
		if err := st.Publish(adapter, r, now); err != nil {
			t.Fatal(err)
		}
	}
	ack := func(adapter, id, outcome string) {
		t.Helper()
		if err := st.Ack(adapter, id, outcome, protocol.Envelope{Alg: "Ed25519", Kid: adapter}, now); err != nil {
			t.Fatal(err)
		}
	}
	publish("ssh", "v1", vince.a.ID(), vince.b.ID())
	publish("ssh", "v2", vince.a.ID())
	publish("web", "k1", kim.a.ID(), kim.b.ID())
	ack("ssh", "v1", protocol.OutcomeApproved)
	ack("ssh", "v2", protocol.OutcomeFailed) // a note: the request stays pending
	ack("ssh", "v2", protocol.OutcomeDenied)
	ack("web", "k1", protocol.OutcomeDenied)

	h := (&API{Store: st}).Handler()
	acks := func(tok string) []string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/v1/device/acks?since=0", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("acks: %d %s", rec.Code, rec.Body)
		}
		var got []AckEntry
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		ids := []string{}
		for _, e := range got {
			ids = append(ids, e.Adapter+"/"+e.RequestID)
		}
		slices.Sort(ids)
		return ids
	}
	for _, tc := range []struct {
		who, tok string
		want     []string
	}{
		{"vince A", vince.tokA, []string{"ssh/v1", "ssh/v2", "ssh/v2"}},
		{"vince B", vince.tokB, []string{"ssh/v1"}},
		{"kim A", kim.tokA, []string{"web/k1"}},
		{"kim B", kim.tokB, []string{"web/k1"}},
	} {
		if got := acks(tc.tok); !slices.Equal(got, tc.want) {
			t.Errorf("%s: acks %v, want %v", tc.who, got, tc.want)
		}
	}

	// kim's unadmitted join is refused the feed at the API (TestPendingJoinIsServedOnlyItsRoster), and has nothing in it.
	if got := st.Acks(c.ID(), time.Unix(0, 0)); len(got) != 0 {
		t.Errorf("kim's unadmitted join: acks %v", got)
	}

	// A device dropped from the hub is dropped from the recipients too.
	if err := st.RevokeDevice(vince.b.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RemoveRevokedDevices(); err != nil {
		t.Fatal(err)
	}
	for _, r := range st.Requests() {
		if slices.Contains(r.Recipients, vince.b.ID()) {
			t.Fatalf("%s still lists the removed device", r.ID)
		}
	}
}
