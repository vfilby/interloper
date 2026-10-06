package warpgate

import (
	"testing"
	"time"

	"github.com/vfilby/interpose/adapters/warpgate/policy"
	"github.com/vfilby/interpose/adapters/warpgate/wgapi"
)

func TestItemDuration(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	s := &Source{
		Policy: policy.Policy{
			Requesters:  map[string]bool{"claude": true},
			MaxDuration: map[policy.Tier]time.Duration{policy.TierRW: 2 * time.Hour, policy.TierAdmin: 30 * time.Minute},
		},
		Now:     func() time.Time { return now },
		users:   map[string]string{"u1": "claude"},
		targets: map[string]string{"t1": "db-01-rw"},
	}
	secs := func(s int64) *int64 { return &s }
	for _, c := range []struct {
		name   string
		secs   *int64
		reason string // "" when allowed
	}{
		{"one hour", secs(3600), ""},
		// time.Duration(18446747674) * time.Second wraps to about 1h0m0.29s.
		{"wraps to 1h", secs(18446747674), "asks for 18446747674s, over the 720h limit for any ticket"},
		{"zero", secs(0), "asks for 0s, not a duration"},
		{"negative", secs(-1), "asks for -1s, not a duration"},
		{"none", nil, "no duration: the ticket would never expire"},
	} {
		t.Run(c.name, func(t *testing.T) {
			it, v := s.item(wgapi.TicketRequest{ID: "r1", UserID: "u1", TargetID: "t1", RequestedDurationSeconds: c.secs, Created: now})
			if v.Deny != (c.reason != "") || v.Reason != c.reason {
				t.Fatalf("verdict %+v, want reason %q", v, c.reason)
			}
			var shown string
			for _, f := range it.Facts {
				if f.Label == "Duration" {
					shown = f.Value
				}
			}
			if c.reason != "" {
				if shown != "" || it.Lease != nil {
					t.Errorf("denied request shows Duration %q, lease %+v", shown, it.Lease)
				}
				return
			}
			if shown != "1h" || it.Lease == nil || it.Lease.DurationS != *c.secs {
				t.Errorf("Duration %q, lease %+v; want 1h, %ds", shown, it.Lease, *c.secs)
			}
		})
	}
}
