package policy

import (
	"testing"
	"time"
)

func TestEvaluate(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	p := Policy{
		Requesters:  map[string]bool{"claude": true, "helper": true},
		MaxDuration: map[Tier]time.Duration{TierRW: 2 * time.Hour, TierAdmin: 30 * time.Minute},
		TTL:         15 * time.Minute,
	}
	dur := func(d time.Duration) *time.Duration { return &d }
	cases := []struct {
		name   string
		req    Request
		deny   bool
		reason string
		host   string
		tier   Tier
	}{
		{"ok rw", Request{"claude", "db-01-rw", dur(2 * time.Hour), now}, false, "", "db-01", TierRW},
		{"ok admin", Request{"helper", "db-01-admin", dur(30 * time.Minute), now.Add(-14 * time.Minute)}, false, "", "db-01", TierAdmin},
		{"unknown user", Request{"", "db-01-rw", dur(time.Hour), now}, true, "requester is not a Warpgate user", "db-01", TierRW},
		{"not allowed", Request{"intruder", "db-01-rw", dur(time.Hour), now}, true, "intruder may not ask for tickets", "db-01", TierRW},
		{"unknown target", Request{"claude", "", dur(time.Hour), now}, true, "target is not a Warpgate target", "", ""},
		{"ro tier", Request{"claude", "db-01-ro", dur(time.Hour), now}, true, "db-01-ro is not an rw or admin tier", "db-01-ro", ""},
		{"own target", Request{"claude", "home", dur(time.Hour), now}, true, "home is not an rw or admin tier", "home", ""},
		{"bare suffix", Request{"claude", "-rw", dur(time.Hour), now}, true, "-rw is not an rw or admin tier", "-rw", ""},
		{"no duration", Request{"claude", "db-01-rw", nil, now}, true, "no duration: the ticket would never expire", "db-01", TierRW},
		{"over cap", Request{"claude", "files-01-admin", dur(2 * time.Hour), now}, true, "asks for 2h, over the 30m cap for admin", "files-01", TierAdmin},
		{"expired", Request{"claude", "files-01-rw", dur(time.Hour), now.Add(-16 * time.Minute)}, true, "unanswered for more than 15m", "files-01", TierRW},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := p.Evaluate(c.req, now)
			if v.Deny != c.deny || v.Reason != c.reason || v.Host != c.host || v.Tier != c.tier {
				t.Errorf("got %+v, want deny=%v reason=%q host=%q tier=%q", v, c.deny, c.reason, c.host, c.tier)
			}
		})
	}
}

func TestHuman(t *testing.T) {
	for d, want := range map[time.Duration]string{
		2 * time.Hour: "2h", 90 * time.Minute: "1h30m", 15 * time.Minute: "15m", 45 * time.Second: "45s", 720 * time.Hour: "720h",
	} {
		if got := Human(d); got != want {
			t.Errorf("Human(%v) = %q, want %q", d, got, want)
		}
	}
}
