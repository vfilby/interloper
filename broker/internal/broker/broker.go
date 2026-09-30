// Package broker is the polling loop: find pending ticket requests, apply the policy, notify the person, audit.
//
// Phase 1 approves nothing. In report mode it only flags what the policy would deny; in enforce mode it denies
// those requests itself. Approval stays with the person in Warpgate's admin UI.
package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
	"unicode"

	"warpgate-approver/broker/internal/audit"
	"warpgate-approver/broker/internal/notify"
	"warpgate-approver/broker/internal/policy"
	"warpgate-approver/broker/internal/warpgate"
)

type Mode string

const (
	ModeReport  Mode = "report"  // notify, and say what the policy would deny; never deny
	ModeEnforce Mode = "enforce" // deny what the policy denies, notify the rest
)

type Config struct {
	Mode         Mode
	Policy       policy.Policy
	ApprovalURL  string        // Warpgate admin UI, tickets page
	StateFile    string        // JSON, rewritten atomically; bounded by the number of pending requests
	NotifyBurst  int           // at most this many request notifications ...
	NotifyWindow time.Duration // ... per window; the rest are collapsed into one warning
	AlertAfter   time.Duration // alert when Warpgate has been unreachable this long
	TokenWarn    time.Duration // alert when the approver token expires within this
	RetryAfter   time.Duration // wait before retrying a failed notification
}

// Warpgate is what the broker needs from warpgate.Client.
type Warpgate interface {
	PendingRequests(ctx context.Context) ([]warpgate.TicketRequest, error)
	Usernames(ctx context.Context) (map[string]string, error)
	TargetNames(ctx context.Context) (map[string]string, error)
	Deny(ctx context.Context, id, reason string) error
	TokenExpiries(ctx context.Context) ([]time.Time, error)
}

// entry is what the broker remembers about one pending request.
type entry struct {
	FirstSeen time.Time `json:"first_seen"`
	Notified  bool      `json:"notified,omitempty"`
	Reported  string    `json:"reported,omitempty"` // report mode: the would-deny reason already sent
	Denied    bool      `json:"denied,omitempty"`
	RetryAt   time.Time `json:"retry_at,omitzero"`
}

type Broker struct {
	cfg   Config
	wg    Warpgate
	n     notify.Notifier
	audit *audit.Log
	log   *slog.Logger

	users, targets map[string]string
	state          map[string]*entry
	saved          []byte

	failingSince time.Time
	alerted      bool

	windowStart time.Time
	windowCount int
	burstWarned bool

	lastTokenCheck time.Time
}

func New(cfg Config, wg Warpgate, n notify.Notifier, a *audit.Log, log *slog.Logger) (*Broker, error) {
	b := &Broker{cfg: cfg, wg: wg, n: n, audit: a, log: log,
		users: map[string]string{}, targets: map[string]string{}, state: map[string]*entry{}}
	data, err := os.ReadFile(cfg.StateFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("reading state: %w", err)
	default:
		if err := json.Unmarshal(data, &b.state); err != nil {
			return nil, fmt.Errorf("state file %s is corrupt (move it away to start fresh): %w", cfg.StateFile, err)
		}
		b.saved = data
	}
	return b, nil
}

// Run polls until ctx ends.
func (b *Broker) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		b.Tick(ctx, time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick is one poll. Exported for tests and for `broker -once`. The error says the poll or a name lookup failed
// (already logged and handled); Run ignores it, -once reports it.
func (b *Broker) Tick(ctx context.Context, now time.Time) error {
	b.checkToken(ctx, now)
	pending, err := b.wg.PendingRequests(ctx)
	if err != nil {
		b.pollFailed(ctx, now, err)
		return err
	}
	b.pollOK(ctx, now)
	namesOK := b.resolveNames(ctx, pending)

	live := make(map[string]bool, len(pending))
	for _, r := range pending {
		live[r.ID] = true
		_, knowU := b.users[r.UserID]
		_, knowT := b.targets[r.TargetID]
		if !namesOK && (!knowU || !knowT) {
			continue // a failed lookup must never turn into "unknown requester, deny": try again next tick
		}
		e := b.state[r.ID]
		if e == nil {
			e = &entry{FirstSeen: now}
			b.state[r.ID] = e
			b.record(now, "seen", r, "")
		}
		b.handle(ctx, now, r, e)
	}
	for id := range b.state {
		if !live[id] {
			b.write(audit.Event{Time: now, Event: "left-pending", RequestID: id})
			delete(b.state, id)
		}
	}
	b.saveState()
	if !namesOK {
		return errors.New("listing Warpgate users or targets failed")
	}
	return nil
}

func (b *Broker) handle(ctx context.Context, now time.Time, r warpgate.TicketRequest, e *entry) {
	req := b.named(r)
	v := b.cfg.Policy.Evaluate(req, now)

	if v.Deny && b.cfg.Mode == ModeEnforce {
		if e.Denied {
			return
		}
		err := b.wg.Deny(ctx, r.ID, "warpgate-approver: "+v.Reason)
		switch {
		case errors.Is(err, warpgate.ErrNotPending):
			e.Denied = true // resolved meanwhile; left-pending is recorded next tick
			return
		case err != nil:
			b.log.Error("deny failed; retrying next poll", "request", r.ID, "err", err)
			return
		}
		e.Denied = true
		b.record(now, "auto-denied", r, v.Reason)
		if b.allowNotify(ctx, now) {
			b.send(ctx, notify.Message{
				Title:    fmt.Sprintf("Denied: %s on %s", req.Requester, req.Target),
				Body:     v.Reason + "\n\n" + reasonLine(req.Requester, r.Description),
				Priority: -1,
			})
		}
		return
	}

	if !e.Notified {
		if now.Before(e.RetryAt) {
			return
		}
		if !b.allowNotify(ctx, now) {
			e.Notified = true
			b.record(now, "notify-suppressed", r, "burst limit")
			return
		}
		if err := b.n.Send(ctx, b.requestMessage(req, r, v, e, now)); err != nil {
			e.RetryAt = now.Add(b.cfg.RetryAfter)
			b.log.Error("notification failed; will retry", "request", r.ID, "err", err)
			return
		}
		e.Notified = true
		detail := ""
		if v.Deny {
			e.Reported = v.Reason
			detail = "policy would deny: " + v.Reason
		}
		b.record(now, "notified", r, detail)
		return
	}

	// Report mode, notified already, and the policy now says deny for a new reason (the TTL ran out).
	if v.Deny && e.Reported != v.Reason {
		e.Reported = v.Reason
		b.record(now, "would-deny", r, v.Reason)
		b.send(ctx, notify.Message{
			Title:    fmt.Sprintf("Policy would deny: %s on %s", req.Requester, req.Target),
			Body:     v.Reason + " (report mode: nothing was denied)",
			URL:      b.cfg.ApprovalURL,
			URLTitle: "Open Warpgate tickets",
			Priority: -1,
		})
	}
}

func (b *Broker) requestMessage(req policy.Request, r warpgate.TicketRequest, v policy.Verdict, e *entry, now time.Time) notify.Message {
	tier := strings.ToUpper(string(v.Tier))
	if tier == "" {
		tier = "access"
	}
	var body strings.Builder
	if v.Deny {
		fmt.Fprintf(&body, "POLICY WOULD DENY: %s (report mode)\n\n", v.Reason)
	}
	fmt.Fprintf(&body, "Target: %s\n", req.Target)
	if req.Duration != nil {
		fmt.Fprintf(&body, "Duration: %s\n", policy.Human(*req.Duration))
	} else {
		body.WriteString("Duration: none (never expires)\n")
	}
	body.WriteString(reasonLine(req.Requester, r.Description) + "\n")
	m := notify.Message{
		Title:    fmt.Sprintf("%s wants %s on %s", req.Requester, tier, v.Host),
		URL:      b.cfg.ApprovalURL,
		URLTitle: "Approve or deny in Warpgate",
	}
	if b.cfg.Mode == ModeEnforce && b.cfg.Policy.TTL > 0 {
		deadline := r.Created.Add(b.cfg.Policy.TTL)
		fmt.Fprintf(&body, "\nDenied automatically if unanswered by %s.", deadline.Local().Format("15:04"))
		m.TTL = deadline.Sub(now)
	}
	m.Body = body.String()
	return m
}

// reasonLine quotes the requester's own words and says whose they are: they are a claim, not a fact.
func reasonLine(requester, description string) string {
	return fmt.Sprintf("Reason given by %s: “%s”", requester, notify.Clip(clean(description), 400))
}

// clean makes requester-written text safe to show: no control characters, one line.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			return ' '
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r): // Cf: bidi overrides and other invisible format chars
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

func (b *Broker) named(r warpgate.TicketRequest) policy.Request {
	req := policy.Request{Requester: b.users[r.UserID], Target: b.targets[r.TargetID], Created: r.Created}
	if r.RequestedDurationSeconds != nil {
		d := time.Duration(*r.RequestedDurationSeconds) * time.Second
		req.Duration = &d
	}
	return req
}

// resolveNames refreshes the id->name maps when a request mentions an id not seen yet. false: a lookup failed.
func (b *Broker) resolveNames(ctx context.Context, pending []warpgate.TicketRequest) bool {
	var needU, needT bool
	for _, r := range pending {
		_, u := b.users[r.UserID]
		_, t := b.targets[r.TargetID]
		needU, needT = needU || !u, needT || !t
	}
	ok := true
	if needU {
		if m, err := b.wg.Usernames(ctx); err != nil {
			b.log.Error("listing users failed", "err", err)
			ok = false
		} else {
			b.users = m
		}
	}
	if needT {
		if m, err := b.wg.TargetNames(ctx); err != nil {
			b.log.Error("listing targets failed", "err", err)
			ok = false
		} else {
			b.targets = m
		}
	}
	return ok
}

func (b *Broker) allowNotify(ctx context.Context, now time.Time) bool {
	if now.Sub(b.windowStart) >= b.cfg.NotifyWindow {
		b.windowStart, b.windowCount, b.burstWarned = now, 0, false
	}
	if b.windowCount < b.cfg.NotifyBurst {
		b.windowCount++
		return true
	}
	if !b.burstWarned {
		b.burstWarned = true
		b.write(audit.Event{Time: now, Event: "burst", Detail: fmt.Sprintf("more than %d requests in %s", b.cfg.NotifyBurst, b.cfg.NotifyWindow)})
		b.send(ctx, notify.Message{
			Title:    "Ticket request burst",
			Body:     fmt.Sprintf("More than %d ticket requests in %s. Further ones are not notified one by one until the window ends; check Warpgate.", b.cfg.NotifyBurst, policy.Human(b.cfg.NotifyWindow)),
			URL:      b.cfg.ApprovalURL,
			URLTitle: "Open Warpgate tickets",
		})
	}
	return false
}

func (b *Broker) pollFailed(ctx context.Context, now time.Time, err error) {
	b.log.Warn("polling Warpgate failed", "err", err)
	if b.failingSince.IsZero() {
		b.failingSince = now
	}
	if b.alerted || now.Sub(b.failingSince) < b.cfg.AlertAfter {
		return
	}
	hint := "Requests are not being watched."
	if errors.Is(err, warpgate.ErrUnauthorized) {
		hint = "The approver token was rejected: mint a new one (wg-apply --mint-token approver)."
	}
	if b.n.Send(ctx, notify.Message{
		Title: "warpgate-approver cannot poll Warpgate",
		Body:  fmt.Sprintf("Failing for %s. %s\n\n%s", policy.Human(now.Sub(b.failingSince)), hint, notify.Clip(err.Error(), 300)),
	}) == nil {
		b.alerted = true
		b.write(audit.Event{Time: now, Event: "warpgate-unreachable", Detail: err.Error()})
	}
}

func (b *Broker) pollOK(ctx context.Context, now time.Time) {
	if b.alerted {
		b.send(ctx, notify.Message{Title: "warpgate-approver is polling Warpgate again", Priority: -1,
			Body: fmt.Sprintf("Back after %s.", policy.Human(now.Sub(b.failingSince)))})
		b.write(audit.Event{Time: now, Event: "warpgate-reachable"})
	}
	b.failingSince, b.alerted = time.Time{}, false
}

func (b *Broker) checkToken(ctx context.Context, now time.Time) {
	if b.cfg.TokenWarn <= 0 || now.Sub(b.lastTokenCheck) < 24*time.Hour {
		return
	}
	b.lastTokenCheck = now
	exps, err := b.wg.TokenExpiries(ctx)
	if err != nil || len(exps) == 0 {
		b.log.Warn("could not read the approver token's expiry", "err", err)
		return
	}
	soonest := exps[0]
	for _, e := range exps[1:] {
		if e.Before(soonest) {
			soonest = e
		}
	}
	if left := soonest.Sub(now); left < b.cfg.TokenWarn {
		b.send(ctx, notify.Message{
			Title: "warpgate-approver token expires soon",
			Body: fmt.Sprintf("The approver's Warpgate token expires %s (in %d days). Mint a new one: wg-apply --mint-token approver.",
				soonest.Local().Format("2006-01-02"), int(left.Hours()/24)),
		})
	}
}

// send is for best-effort messages (alerts, follow-ups): a failure is logged, not retried.
func (b *Broker) send(ctx context.Context, m notify.Message) {
	if err := b.n.Send(ctx, m); err != nil {
		b.log.Error("notification failed", "title", m.Title, "err", err)
	}
}

func (b *Broker) record(now time.Time, event string, r warpgate.TicketRequest, detail string) {
	req := b.named(r)
	b.write(audit.Event{Time: now, Event: event, RequestID: r.ID, Requester: req.Requester, Target: req.Target,
		DurationS: r.RequestedDurationSeconds, Description: r.Description, Detail: detail})
}

func (b *Broker) write(e audit.Event) {
	if err := b.audit.Write(e); err != nil {
		b.log.Error("audit write failed", "event", e.Event, "err", err)
	}
}

func (b *Broker) saveState() {
	data, err := json.Marshal(b.state)
	if err != nil || bytes.Equal(data, b.saved) {
		return
	}
	tmp := b.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		b.log.Error("saving state failed", "err", err)
		return
	}
	if err := os.Rename(tmp, b.cfg.StateFile); err != nil {
		b.log.Error("saving state failed", "err", err)
		return
	}
	b.saved = data
}
