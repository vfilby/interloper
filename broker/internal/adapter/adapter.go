// Package adapter is the part of the clearing house that sits next to a service and holds its credential. It turns
// the service's pending items into signed, sealed records; it alone decides whether a device's decision is valid; and
// only then does it act. A Source supplies the service-specific half (Warpgate, Mailpit, Paperless, demo).
package adapter

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"warpgate-approver/broker/internal/audit"
	"warpgate-approver/broker/internal/protocol"
)

// Item is one thing at the service waiting for a person, described from the service's own state.
type Item struct {
	Key        string              `json:"key"` // the service's id for it; stable while it is pending
	Kind       string              `json:"kind"`
	Shape      string              `json:"shape"`
	Risk       string              `json:"risk"`
	Title      string              `json:"title"`
	Requester  string              `json:"requester"`
	OnBehalfOf *protocol.Principal `json:"on_behalf_of,omitempty"`
	Facts      []protocol.Fact     `json:"facts"`
	Reason     string              `json:"reason"`
	Lease      *protocol.Lease     `json:"lease,omitempty"`
	Expires    time.Time           `json:"-"` // zero: the adapter's default TTL
}

// ErrGone: the item is no longer pending at the service.
var ErrGone = errors.New("no longer pending at the service")

// Source is the service-specific half of an adapter.
type Source interface {
	// Pending lists what needs a person now, after the source's own policy (which may deny by itself).
	Pending(ctx context.Context) ([]Item, error)
	// Current re-reads one item just before acting. ok false: no longer pending.
	Current(ctx context.Context, key string) (it Item, ok bool, err error)
	Approve(ctx context.Context, key string) error
	Deny(ctx context.Context, key, reason string) error
}

type Config struct {
	ID        string
	Key       ed25519.PrivateKey
	StateFile string
	TTL       time.Duration // default record lifetime
	Poll      time.Duration
	Now       func() time.Time // nil: time.Now (tests)
}

// open is a record sent out and not yet final.
type open struct {
	Key       string          `json:"key"`
	ItemHash  string          `json:"item_hash"` // the service's view when the record was made
	Payload   []byte          `json:"payload"`   // exact signed record bytes; record_hash covers these
	Record    protocol.Record `json:"record"`
	Published bool            `json:"published"`
}

type Adapter struct {
	cfg   Config
	src   Source
	hub   *HubClient
	trust *Trust
	audit *audit.Log
	log   *slog.Logger
	now   func() time.Time

	mu   sync.Mutex
	open map[string]*open // by record id
}

func New(cfg Config, src Source, hub *HubClient, trust *Trust, a *audit.Log, log *slog.Logger) (*Adapter, error) {
	ad := &Adapter{cfg: cfg, src: src, hub: hub, trust: trust, audit: a, log: log, now: cfg.Now, open: map[string]*open{}}
	if ad.now == nil {
		ad.now = time.Now
	}
	b, err := os.ReadFile(cfg.StateFile)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &ad.open); err != nil {
			return nil, fmt.Errorf("adapter state %s is corrupt: %w", cfg.StateFile, err)
		}
	}
	return ad, nil
}

// Run polls the source and serves decisions until ctx ends.
func (ad *Adapter) Run(ctx context.Context) {
	go ad.decisionLoop(ctx)
	t := time.NewTicker(ad.cfg.Poll)
	defer t.Stop()
	for {
		if err := ad.Tick(ctx); err != nil {
			ad.log.Warn("tick", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func itemHash(it Item) string {
	b, _ := json.Marshal(it)
	return protocol.B64(protocol.Hash(b))
}

// Tick publishes new items, retries unpublished ones, and closes records that ended outside the clearing house or
// ran out of time.
func (ad *Adapter) Tick(ctx context.Context) error {
	if err := ad.trust.Reload(); err != nil {
		return fmt.Errorf("trust list: %w", err) // fail closed: no publishing with an unreadable list
	}
	items, err := ad.src.Pending(ctx)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	now := ad.now()
	live := map[string]Item{}
	for _, it := range items {
		live[it.Key] = it
	}

	ad.mu.Lock()
	byKey := map[string]*open{}
	for _, o := range ad.open {
		byKey[o.Key] = o
	}
	ad.mu.Unlock()

	for _, it := range items {
		if byKey[it.Key] != nil {
			continue
		}
		o, err := ad.newRecord(it, now)
		if err != nil {
			ad.log.Error("building record", "key", it.Key, "err", err)
			continue
		}
		ad.mu.Lock()
		ad.open[o.Record.ID] = o
		ad.mu.Unlock()
		byKey[it.Key] = o
		ad.write(audit.Event{Time: now, Event: "record", RequestID: o.Record.ID, Requester: it.Requester,
			Target: it.Key, Description: it.Reason, Detail: it.Title})
	}

	ad.mu.Lock()
	var work []*open
	for _, o := range ad.open {
		work = append(work, o)
	}
	ad.mu.Unlock()

	for _, o := range work {
		switch {
		case live[o.Key].Key == "":
			ad.finish(ctx, o, protocol.OutcomeExpired, "resolved outside the clearing house", nil)
		case now.Unix() > o.Record.ExpiresAt:
			// Fail closed: unanswered means denied at the service.
			if err := ad.src.Deny(ctx, o.Key, "unanswered before "+time.Unix(o.Record.ExpiresAt, 0).Format(time.RFC3339)); err != nil && !errors.Is(err, ErrGone) {
				ad.log.Error("denying expired item", "key", o.Key, "err", err)
				continue
			}
			ad.finish(ctx, o, protocol.OutcomeExpired, "unanswered; denied", nil)
		case !o.Published:
			ad.publish(ctx, o)
		}
	}
	ad.save()
	return nil
}

func (ad *Adapter) newRecord(it Item, now time.Time) (*open, error) {
	exp := it.Expires
	if exp.IsZero() {
		exp = now.Add(ad.cfg.TTL)
	}
	idb := protocol.NewNonce()
	rec := protocol.Record{V: protocol.Version, ID: idb, Adapter: ad.cfg.ID, Kind: it.Kind, Shape: it.Shape,
		Risk: it.Risk, Title: it.Title, Requester: it.Requester, OnBehalfOf: it.OnBehalfOf, Facts: it.Facts,
		Reason: it.Reason, Lease: it.Lease, CreatedAt: now.Unix(), ExpiresAt: exp.Unix(), Nonce: protocol.NewNonce()}
	if rec.Shape == "" {
		rec.Shape = protocol.ShapeOnce
	}
	if rec.Risk == "" {
		rec.Risk = protocol.RiskNormal
	}
	env, err := protocol.SignEd25519(ad.cfg.Key, ad.cfg.ID, rec)
	if err != nil {
		return nil, err
	}
	p, _ := env.PayloadBytes()
	return &open{Key: it.Key, ItemHash: itemHash(it), Payload: p, Record: rec}, nil
}

// publish seals the record for every trusted device and hands it to the hub.
func (ad *Adapter) publish(ctx context.Context, o *open) {
	cards := ad.trust.Cards()
	if len(cards) == 0 {
		ad.log.Warn("no trusted devices: nobody can be asked", "request", o.Record.ID)
		return
	}
	env := protocol.Envelope{Alg: protocol.AlgEd25519, Kid: ad.cfg.ID, Payload: protocol.B64(o.Payload),
		Sig: protocol.B64(ed25519.Sign(ad.cfg.Key, o.Payload))}
	boxes := map[string]protocol.Sealed{}
	for _, c := range cards {
		ek, _ := protocol.UnB64(c.EncKey)
		s, err := protocol.Seal(nil, c.DeviceID, ek, env)
		if err != nil {
			ad.log.Error("sealing", "device", c.DeviceID, "err", err)
			continue
		}
		boxes[c.DeviceID] = s
	}
	err := ad.hub.Publish(ctx, PublishRequest{ID: o.Record.ID, Kind: o.Record.Kind, CreatedAt: o.Record.CreatedAt,
		ExpiresAt: o.Record.ExpiresAt, Boxes: boxes})
	if err != nil {
		ad.log.Warn("publishing to hub; will retry", "request", o.Record.ID, "err", err)
		return
	}
	ad.mu.Lock()
	o.Published = true
	ad.mu.Unlock()
	ad.write(audit.Event{Time: ad.now(), Event: "published", RequestID: o.Record.ID, Detail: fmt.Sprintf("%d devices", len(boxes))})
}

func (ad *Adapter) decisionLoop(ctx context.Context) {
	for ctx.Err() == nil {
		ds, err := ad.hub.Decisions(ctx, 25*time.Second)
		if err != nil {
			if ctx.Err() == nil {
				ad.log.Warn("waiting for decisions", "err", err)
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
				}
			}
			continue
		}
		for _, d := range ds {
			ad.Handle(ctx, d)
		}
		ad.save()
	}
}

// Handle judges one decision and, if it holds, acts on it. Exported for tests.
func (ad *Adapter) Handle(ctx context.Context, q QueuedDecision) {
	now := ad.now()
	ad.mu.Lock()
	o := ad.open[q.RequestID]
	ad.mu.Unlock()
	reject := func(why string) {
		ad.write(audit.Event{Time: now, Event: "decision-rejected", RequestID: q.RequestID, Device: q.DeviceID, Detail: why})
		if o != nil {
			ad.sendAck(ctx, o, protocol.OutcomeRejected, why, q.Decision)
		}
	}
	if o == nil {
		reject("unknown or already decided request")
		return
	}
	card, ok := ad.trust.Card(q.Decision.Kid)
	if !ok {
		reject("device " + q.Decision.Kid + " is not trusted by this adapter")
		return
	}
	d, err := protocol.VerifyDecision(q.Decision, card, ad.cfg.ID, o.Payload, o.Record, now)
	if err != nil {
		reject(err.Error())
		return
	}

	// The service's state is the last word: still pending, and still what the person was shown.
	cur, ok, err := ad.src.Current(ctx, o.Key)
	switch {
	case err != nil:
		ad.sendAck(ctx, o, protocol.OutcomeFailed, "could not re-check the service: "+err.Error(), q.Decision)
		return
	case !ok:
		ad.finish(ctx, o, protocol.OutcomeExpired, "no longer pending at the service", &q.Decision)
		return
	case itemHash(cur) != o.ItemHash:
		// Close this record; the next tick sends a fresh one describing the request as it is now.
		ad.finish(ctx, o, protocol.OutcomeExpired, "the request changed after it was shown; sent again", &q.Decision)
		return
	}

	if d.Decision == protocol.Approve {
		err = ad.src.Approve(ctx, o.Key)
	} else {
		err = ad.src.Deny(ctx, o.Key, "denied by "+card.Name)
	}
	switch {
	case errors.Is(err, ErrGone):
		ad.finish(ctx, o, protocol.OutcomeExpired, "no longer pending at the service", &q.Decision)
	case err != nil:
		ad.sendAck(ctx, o, protocol.OutcomeFailed, err.Error(), q.Decision)
	case d.Decision == protocol.Approve:
		ad.finish(ctx, o, protocol.OutcomeApproved, "approved on "+card.Name, &q.Decision)
	default:
		ad.finish(ctx, o, protocol.OutcomeDenied, "denied on "+card.Name, &q.Decision)
	}
}

// finish sends a final ack and forgets the record: its nonce can never be used again.
func (ad *Adapter) finish(ctx context.Context, o *open, outcome, detail string, dec *protocol.Envelope) {
	ad.mu.Lock()
	_, still := ad.open[o.Record.ID]
	delete(ad.open, o.Record.ID)
	ad.mu.Unlock()
	if !still {
		return // the poll loop and the decision loop raced; the other one finished it
	}
	var de protocol.Envelope
	if dec != nil {
		de = *dec
	}
	ad.write(audit.Event{Time: ad.now(), Event: outcome, RequestID: o.Record.ID, Target: o.Key, Device: de.Kid, Detail: detail})
	if o.Published {
		ad.sendAck(ctx, o, outcome, detail, de)
	}
}

func (ad *Adapter) sendAck(ctx context.Context, o *open, outcome, detail string, dec protocol.Envelope) {
	dh := ""
	if p, err := dec.PayloadBytes(); err == nil && len(p) > 0 {
		dh = protocol.B64(protocol.Hash(p))
	}
	ack, err := protocol.SignEd25519(ad.cfg.Key, ad.cfg.ID, protocol.Ack{V: protocol.Version, RequestID: o.Record.ID,
		Adapter: ad.cfg.ID, Outcome: outcome, Detail: detail, DecisionHash: dh, TS: ad.now().Unix()})
	if err == nil {
		err = ad.hub.Ack(ctx, o.Record.ID, ack)
	}
	if err != nil {
		ad.log.Warn("ack to hub failed", "request", o.Record.ID, "outcome", outcome, "err", err)
	}
}

// Open lists the records not yet final, for status output.
func (ad *Adapter) Open() []protocol.Record {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	out := make([]protocol.Record, 0, len(ad.open))
	for _, o := range ad.open {
		out = append(out, o.Record)
	}
	return out
}

func (ad *Adapter) save() {
	ad.mu.Lock()
	b, err := json.Marshal(ad.open)
	ad.mu.Unlock()
	if err != nil {
		return
	}
	tmp := ad.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		err = os.Rename(tmp, ad.cfg.StateFile)
	}
	if err != nil {
		ad.log.Error("saving adapter state", "err", err)
	}
}

func (ad *Adapter) write(e audit.Event) {
	e.Adapter = ad.cfg.ID
	if ad.audit == nil {
		return
	}
	if err := ad.audit.Write(e); err != nil {
		ad.log.Error("audit write failed", "event", e.Event, "err", err)
	}
}
