// Package warpgate is the Warpgate Source of the Warpgate adapter: pending ticket requests become records, the phase-1 policy still denies
// what it always denied before a person is asked, and a verified approval calls Warpgate's approve.
package warpgate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/vfilby/interloper/adapter"
	"github.com/vfilby/interloper/adapters/warpgate/policy"
	"github.com/vfilby/interloper/adapters/warpgate/wgapi"
	"github.com/vfilby/interloper/internal/protocol"
)

// Warpgate is what the source needs from wgapi.Client.
type Warpgate interface {
	PendingRequests(ctx context.Context) ([]wgapi.TicketRequest, error)
	Usernames(ctx context.Context) (map[string]string, error)
	TargetNames(ctx context.Context) (map[string]string, error)
	Approve(ctx context.Context, id string) error
	Deny(ctx context.Context, id, reason string) error
}

type Source struct {
	WG     Warpgate
	Policy policy.Policy
	Now    func() time.Time

	mu             sync.Mutex
	users, targets map[string]string
}

func (s *Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// names refreshes the id->name maps when needed. A failed lookup is an error, never "unknown, deny".
func (s *Source) names(ctx context.Context, rs []wgapi.TicketRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var needU, needT bool
	for _, r := range rs {
		_, u := s.users[r.UserID]
		_, t := s.targets[r.TargetID]
		needU, needT = needU || !u, needT || !t
	}
	if needU {
		m, err := s.WG.Usernames(ctx)
		if err != nil {
			return err
		}
		s.users = m
	}
	if needT {
		m, err := s.WG.TargetNames(ctx)
		if err != nil {
			return err
		}
		s.targets = m
	}
	return nil
}

func (s *Source) Pending(ctx context.Context) ([]adapter.Item, error) {
	rs, err := s.WG.PendingRequests(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.names(ctx, rs); err != nil {
		return nil, err
	}
	var out []adapter.Item
	for _, r := range rs {
		it, v := s.item(r)
		if v.Deny {
			// The policy's verdict, as in phase 1 enforce mode: nobody is asked about a request it rejects.
			if err := s.WG.Deny(ctx, r.ID, "clearing house: "+v.Reason); err != nil && !errors.Is(err, wgapi.ErrNotPending) {
				return nil, fmt.Errorf("denying %s by policy: %w", r.ID, err)
			}
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

func (s *Source) Current(ctx context.Context, key string) (adapter.Item, bool, error) {
	rs, err := s.WG.PendingRequests(ctx)
	if err != nil {
		return adapter.Item{}, false, err
	}
	for _, r := range rs {
		if r.ID == key {
			if err := s.names(ctx, rs); err != nil {
				return adapter.Item{}, false, err
			}
			it, v := s.item(r)
			if v.Deny {
				return adapter.Item{}, false, nil
			}
			return it, true, nil
		}
	}
	return adapter.Item{}, false, nil
}

func (s *Source) Approve(ctx context.Context, key string) error { return gone(s.WG.Approve(ctx, key)) }

func (s *Source) Deny(ctx context.Context, key, reason string) error {
	return gone(s.WG.Deny(ctx, key, "clearing house: "+reason))
}

func gone(err error) error {
	if errors.Is(err, wgapi.ErrNotPending) {
		return adapter.ErrGone
	}
	return err
}

// item describes a ticket request from Warpgate's own data. Everything but Reason is authoritative.
func (s *Source) item(r wgapi.TicketRequest) (adapter.Item, policy.Verdict) {
	s.mu.Lock()
	req := policy.Request{Requester: s.users[r.UserID], Target: s.targets[r.TargetID], Created: r.Created}
	s.mu.Unlock()
	if r.RequestedDurationSeconds != nil {
		d := time.Duration(*r.RequestedDurationSeconds) * time.Second
		req.Duration = &d
	}
	v := s.Policy.Evaluate(req, s.now())
	tier := strings.ToUpper(string(v.Tier))
	risk, level := protocol.RiskElevated, "warn"
	if v.Tier == policy.TierAdmin {
		risk, level = protocol.RiskHigh, "danger"
	}
	it := adapter.Item{
		Key:       r.ID,
		Kind:      "ssh.ticket",
		Shape:     protocol.ShapeLease,
		Risk:      risk,
		Title:     fmt.Sprintf("%s wants %s on %s", req.Requester, tier, v.Host),
		Requester: req.Requester,
		Facts: []protocol.Fact{
			{Label: "Host", Value: v.Host},
			{Label: "Access", Value: tier, Level: level},
			{Label: "Target", Value: req.Target},
		},
		Reason: r.Description,
	}
	if req.Duration != nil {
		it.Facts = append(it.Facts, protocol.Fact{Label: "Duration", Value: policy.Human(*req.Duration)})
		it.Lease = &protocol.Lease{DurationS: int64(req.Duration.Seconds()), Scope: req.Target}
	}
	if s.Policy.TTL > 0 {
		it.Expires = r.Created.Add(s.Policy.TTL)
	}
	return it, v
}
