// Package demo is a Source with no real service behind it: requests are added over a loopback HTTP endpoint and
// "approving" only records the outcome. For LAN testing of the hub, the app and the protocol end to end.
package demo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"warpgate-approver/broker/internal/adapter"
	"warpgate-approver/broker/internal/protocol"
)

type entry struct {
	Item    adapter.Item `json:"item"`
	Outcome string       `json:"outcome,omitempty"` // "", approved, denied
	Reason  string       `json:"reason,omitempty"`
	At      time.Time    `json:"at,omitzero"`
}

type Source struct {
	mu   sync.Mutex
	seq  int
	reqs map[string]*entry
}

func New() *Source { return &Source{reqs: map[string]*entry{}} }

// Add queues a request as if a service had one pending. Empty fields get demo defaults.
func (s *Source) Add(it adapter.Item) adapter.Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	it.Key = fmt.Sprintf("demo-%d", s.seq)
	if it.Kind == "" {
		it.Kind = "demo.request"
	}
	if it.Title == "" {
		it.Title = it.Requester + " wants something"
	}
	if it.Facts == nil {
		it.Facts = []protocol.Fact{{Label: "Service", Value: "demo"}}
	}
	s.reqs[it.Key] = &entry{Item: it}
	return it
}

func (s *Source) Pending(context.Context) ([]adapter.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []adapter.Item
	for _, e := range s.reqs {
		if e.Outcome == "" {
			out = append(out, e.Item)
		}
	}
	return out, nil
}

func (s *Source) Current(_ context.Context, key string) (adapter.Item, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.reqs[key]
	if !ok || e.Outcome != "" {
		return adapter.Item{}, false, nil
	}
	return e.Item, true, nil
}

func (s *Source) resolve(key, outcome, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.reqs[key]
	if !ok || e.Outcome != "" {
		return adapter.ErrGone
	}
	e.Outcome, e.Reason, e.At = outcome, reason, time.Now()
	return nil
}

func (s *Source) Approve(_ context.Context, key string) error { return s.resolve(key, "approved", "") }

func (s *Source) Deny(_ context.Context, key, reason string) error {
	return s.resolve(key, "denied", reason)
}

// Handler: POST /requests {requester, title, reason, risk, facts, ...} adds one; GET /requests lists all with outcomes.
// Bind it to loopback only: it is the "service", and anyone who can reach it can make requests.
func (s *Source) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /requests", func(w http.ResponseWriter, r *http.Request) {
		var it adapter.Item
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&it); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.Add(it))
	})
	m.HandleFunc("GET /requests", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		out := make([]*entry, 0, len(s.reqs))
		for _, e := range s.reqs {
			c := *e
			out = append(out, &c)
		}
		s.mu.Unlock()
		sort.Slice(out, func(i, j int) bool { return out[i].Item.Key < out[j].Item.Key })
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	return m
}

// Mutate changes a pending item in place, as a service-side edit would (tests).
func (s *Source) Mutate(key string, f func(*adapter.Item)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.reqs[key]; ok {
		f(&e.Item)
	}
}
