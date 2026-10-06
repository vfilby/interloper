package e2e_test

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vfilby/interpose/adapter"
	"github.com/vfilby/interpose/internal/audit"
	"github.com/vfilby/interpose/internal/protocol"
)

// countAcks counts the acks the adapter POSTs to the hub.
type countAcks struct {
	n atomic.Int64
}

func (c *countAcks) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/adapter/acks") {
		c.n.Add(1)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func (w *world) auditEvents() (out []audit.Event, longest int) {
	w.t.Helper()
	f, err := os.Open(w.audit)
	if err != nil {
		w.t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(nil, 16<<20)
	for s.Scan() {
		longest = max(longest, len(s.Bytes()))
		var e audit.Event
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			w.t.Fatal(err)
		}
		out = append(out, e)
	}
	return out, longest
}

func count(evs []audit.Event, event string) int {
	n := 0
	for _, e := range evs {
		if e.Event == event {
			n++
		}
	}
	return n
}

// A hub that answers every long-poll with thousands of junk decisions gets a bounded number of audit entries and
// acks out of it, and nothing it chose longer than an id.
func TestHostileHubCannotFillTheAuditLog(t *testing.T) {
	w := newWorld(t)
	acks := &countAcks{}
	w.adHub.HTTP = &http.Client{Transport: acks}
	it, o := w.openOne(w.phone, w.phoneHub, "x")
	strDec, _ := w.stranger.Decide(o, protocol.Approve, w.clock())
	before, _ := w.auditEvents()

	huge := strings.Repeat("A", 1<<20)
	junkKid := protocol.Envelope{Alg: protocol.AlgES256, Kid: "0123456789abcdef", Payload: "e30", Sig: "AA"}
	var flood []adapter.QueuedDecision
	for range 3000 { // unknown requests
		flood = append(flood, adapter.QueuedDecision{Adapter: "demo", RequestID: protocol.NewRequestID(), DeviceID: huge, Decision: junkKid})
	}
	for range 200 { // the real request, a kid no one trusts
		flood = append(flood, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: w.phone.ID(), Decision: junkKid})
	}
	for range 200 { // the real request, a kid the hub made up at length
		flood = append(flood, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID,
			Decision: protocol.Envelope{Alg: protocol.AlgES256, Kid: huge, Payload: "e30", Sig: "AA"}})
	}
	for range 200 { // a request id the hub made up at length
		flood = append(flood, adapter.QueuedDecision{Adapter: "demo", RequestID: huge, Decision: junkKid})
	}
	for range 5 { // a hub that keeps sending, poll after poll
		w.ad.HandleAll(w.ctx, flood)
	}

	evs, longest := w.auditEvents()
	evs = evs[len(before):]
	if longest > 2048 {
		t.Errorf("an audit line of %d bytes: hub-chosen text was logged", longest)
	}
	if n := count(evs, "decision-rejected"); n > 40 {
		t.Errorf("%d decision-rejected entries from one flood; want at most two bursts of 20", n)
	}
	if n := count(evs, "decisions-not-logged"); n != 1 {
		t.Errorf("%d decisions-not-logged summaries; want 1 within a minute", n)
	}
	if n := acks.n.Load(); n > 20 {
		t.Errorf("%d acks sent for rejected decisions; want at most a burst of 20", n)
	}
	for _, e := range evs {
		if e.Event == "decision-rejected" && (!e.Unverified || e.Device == w.phone.ID()) {
			t.Errorf("rejected entry names the hub's device_id or is not marked unverified: %+v", e)
		}
		if e.Event == "decisions-not-logged" && !strings.Contains(e.Detail, "over the 500-per-poll cap") {
			t.Errorf("summary %q", e.Detail)
		}
	}

	// The budget comes back with time, and the summary is written for what was dropped since.
	w.advance(2 * time.Minute)
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: w.phone.ID(), Decision: strDec})
	w.ad.HandleAll(w.ctx, flood[:10])
	evs, _ = w.auditEvents()
	last := evs[len(evs)-1]
	if last.Event != "decisions-not-logged" {
		t.Errorf("no summary after the flood: %+v", last)
	}
	var framed *audit.Event
	for i := range evs {
		if evs[i].Event == "decision-rejected" && evs[i].Device == w.stranger.ID() {
			framed = &evs[i]
		}
	}
	// The hub said the phone sent it; the envelope says the stranger did; the log says the stranger, unverified.
	if framed == nil || !framed.Unverified || !strings.Contains(framed.Detail, "not on the roster") {
		t.Errorf("the stranger's decision was not logged under its own kid, unverified: %+v", framed)
	}

	// None of it got in the way of the person deciding.
	if w.outcome(it.Key) != "pending" {
		t.Fatal("junk acted on the service")
	}
	w.decide(w.phone, o, protocol.Approve)
	if w.outcome(it.Key) != "resolved" {
		t.Fatal("the phone's approval after the flood did nothing")
	}
}
