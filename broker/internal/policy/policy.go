// Package policy decides, before any human sees a request, whether it is one the broker must deny.
package policy

import (
	"fmt"
	"strings"
	"time"
)

type Tier string

const (
	TierRW    Tier = "rw"
	TierAdmin Tier = "admin"
)

type Policy struct {
	Requesters  map[string]bool        // Warpgate usernames allowed to ask (claude, helper)
	MaxDuration map[Tier]time.Duration // Warpgate's approve cannot shorten a ticket, so longer asks are denied
	TTL         time.Duration          // unanswered longer than this: denied
}

// Request is a ticket request with its ids resolved. Requester/Target are "" when Warpgate does not know the id.
type Request struct {
	Requester string
	Target    string
	Duration  *time.Duration // nil: the ticket would never expire
	Created   time.Time
}

type Verdict struct {
	Deny   bool
	Reason string
	Host   string // target without its tier suffix (the whole name if it has none)
	Tier   Tier   // "" when the target is not a ticket tier
}

// SplitTarget splits "build-01-admin" into ("build-01", admin). ok is false for anything but *-rw / *-admin.
func SplitTarget(name string) (host string, tier Tier, ok bool) {
	for _, t := range []Tier{TierAdmin, TierRW} {
		if h, found := strings.CutSuffix(name, "-"+string(t)); found && h != "" {
			return h, t, true
		}
	}
	return name, "", false
}

func (p Policy) Evaluate(r Request, now time.Time) Verdict {
	host, tier, ok := SplitTarget(r.Target)
	v := Verdict{Host: host, Tier: tier}
	deny := func(format string, a ...any) Verdict {
		v.Deny, v.Reason = true, fmt.Sprintf(format, a...)
		return v
	}
	switch {
	case r.Requester == "":
		return deny("requester is not a Warpgate user")
	case !p.Requesters[r.Requester]:
		return deny("%s may not ask for tickets", r.Requester)
	case r.Target == "":
		return deny("target is not a Warpgate target")
	case !ok:
		return deny("%s is not an rw or admin tier", r.Target)
	case r.Duration == nil:
		return deny("no duration: the ticket would never expire")
	case *r.Duration > p.MaxDuration[tier]:
		return deny("asks for %s, over the %s cap for %s", Human(*r.Duration), Human(p.MaxDuration[tier]), tier)
	case p.TTL > 0 && now.Sub(r.Created) > p.TTL:
		return deny("unanswered for more than %s", Human(p.TTL))
	}
	return v
}

// Human formats 2h0m0s as "2h", 1h30m0s as "1h30m", 45s as "45s".
func Human(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	d = d.Round(time.Minute)
	h, m := int(d.Hours()), int(d.Minutes())%60
	switch {
	case h == 0:
		return fmt.Sprintf("%dm", m)
	case m == 0:
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}
