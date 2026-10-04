// Package hub is the clearing house's relay: it stores sealed requests, signed decisions and signed acks, and
// moves them between adapters and devices. It holds no key that can approve anything and cannot read a record:
// a hostile hub can drop or delay, nothing more (docs/PROTOCOL.md).
package hub

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"warpgate-approver/broker/internal/protocol"
)

// Bounds. The hub is reachable by every adapter and device; nothing it keeps may grow without limit.
const (
	MaxPendingPerAdapter = 200
	MaxBoxBytes          = 64 << 10
	MaxDecisionsQueued   = 500
	KeepResolved         = 24 * time.Hour
	EnrollCodeTTL        = 10 * time.Minute
)

var (
	ErrUnknown  = errors.New("not found")
	ErrTooMany  = errors.New("too many pending requests for this adapter")
	ErrConflict = errors.New("already exists")
)

type Adapter struct {
	ID        string    `json:"id"`
	Key       string    `json:"key"` // Ed25519 public key, b64; the app pins it on first use
	TokenHash string    `json:"token_hash"`
	AddedAt   time.Time `json:"added_at"`
	LastSeen  time.Time `json:"last_seen,omitzero"`
}

type Device struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Card       protocol.Envelope `json:"card"`
	TokenHash  string            `json:"token_hash"`
	EnrolledAt time.Time         `json:"enrolled_at"`
	LastSeen   time.Time         `json:"last_seen,omitzero"`
	Revoked    bool              `json:"revoked,omitempty"`
}

type Request struct {
	Adapter   string                     `json:"adapter"`
	ID        string                     `json:"id"`
	Kind      string                     `json:"kind"`
	CreatedAt int64                      `json:"created_at"`
	ExpiresAt int64                      `json:"expires_at"`
	Boxes     map[string]protocol.Sealed `json:"boxes"`
	// Set once the adapter acks: the request is no longer shown to devices.
	Ack        *protocol.Envelope `json:"ack,omitempty"`
	ResolvedAt time.Time          `json:"resolved_at,omitzero"`
	Decisions  int                `json:"decisions"` // how many decisions devices have sent (for the UI)
	Notes      []Note             `json:"notes,omitempty"`
}

type QueuedDecision struct {
	Adapter   string            `json:"adapter"`
	RequestID string            `json:"request_id"`
	DeviceID  string            `json:"device_id"`
	Decision  protocol.Envelope `json:"decision"`
	At        time.Time         `json:"at"`
}

type enrollCode struct {
	Hash    string    `json:"hash"`
	Expires time.Time `json:"expires"`
}

type state struct {
	Adapters  map[string]*Adapter `json:"adapters"`
	Devices   map[string]*Device  `json:"devices"`
	Requests  map[string]*Request `json:"requests"` // adapter + "/" + id
	Decisions []QueuedDecision    `json:"decisions"`
	Codes     []enrollCode        `json:"codes"`
}

// Store is the hub's state: in memory, written through to one JSON file. The file is bounded by the limits above.
type Store struct {
	mu      sync.Mutex
	path    string
	s       state
	changed chan struct{} // closed and replaced on every change; long-polls wait on it
}

func Open(path string) (*Store, error) {
	st := &Store{path: path, changed: make(chan struct{}),
		s: state{Adapters: map[string]*Adapter{}, Devices: map[string]*Device{}, Requests: map[string]*Request{}}}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &st.s); err != nil {
			return nil, fmt.Errorf("hub state %s is corrupt: %w", path, err)
		}
		if st.s.Adapters == nil {
			st.s.Adapters = map[string]*Adapter{}
		}
		if st.s.Devices == nil {
			st.s.Devices = map[string]*Device{}
		}
		if st.s.Requests == nil {
			st.s.Requests = map[string]*Request{}
		}
	}
	return st, nil
}

// commit saves and wakes waiters. Called with mu held.
func (st *Store) commit() error {
	close(st.changed)
	st.changed = make(chan struct{})
	b, err := json.Marshal(st.s)
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}

// Changed returns a channel closed at the next change.
func (st *Store) Changed() <-chan struct{} {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.changed
}

// ---- tokens and codes ----

// NewSecret returns a random token and the hash the hub keeps of it.
func NewSecret() (secret, hash string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	secret = protocol.B64(b)
	return secret, hashSecret(secret)
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return protocol.B64(h[:])
}

func sameHash(secret, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(hash)) == 1
}

// ---- adapters ----

// AddAdapter registers an adapter's id and public key and returns its hub token (shown once).
func (st *Store) AddAdapter(id, key string, now time.Time) (string, error) {
	raw, err := protocol.UnB64(key)
	if err != nil || len(raw) != 32 {
		return "", errors.New("adapter key must be a base64url Ed25519 public key")
	}
	if !validID(id) {
		return "", errors.New("adapter id: 1-40 of a-z 0-9 . _ -")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.s.Adapters[id]; ok {
		return "", ErrConflict
	}
	tok, h := NewSecret()
	st.s.Adapters[id] = &Adapter{ID: id, Key: key, TokenHash: h, AddedAt: now}
	return tok, st.commit()
}

func (st *Store) RemoveAdapter(id string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.s.Adapters[id]; !ok {
		return ErrUnknown
	}
	delete(st.s.Adapters, id)
	for k, r := range st.s.Requests {
		if r.Adapter == id {
			delete(st.s.Requests, k)
		}
	}
	return st.commit()
}

func (st *Store) AdapterByToken(tok string, now time.Time) (*Adapter, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, a := range st.s.Adapters {
		if sameHash(tok, a.TokenHash) {
			if now.Sub(a.LastSeen) > time.Minute { // keep writes down: last-seen is coarse
				a.LastSeen = now
				_ = st.commit()
			}
			c := *a
			return &c, true
		}
	}
	return nil, false
}

func (st *Store) Adapters() []Adapter {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Adapter, 0, len(st.s.Adapters))
	for _, a := range st.s.Adapters {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ---- devices ----

// NewEnrollCode returns a one-time enrollment code.
func (st *Store) NewEnrollCode(now time.Time) (string, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	code, h := NewSecret()
	live := st.s.Codes[:0]
	for _, c := range st.s.Codes {
		if now.Before(c.Expires) {
			live = append(live, c)
		}
	}
	if len(live) >= 10 {
		return "", errors.New("too many open enrollment codes; wait for them to expire")
	}
	st.s.Codes = append(live, enrollCode{Hash: h, Expires: now.Add(EnrollCodeTTL)})
	return code, st.commit()
}

// Enroll spends a code and registers the device card. Returns the device's hub token.
func (st *Store) Enroll(code string, card protocol.Envelope, now time.Time) (protocol.DeviceCard, string, error) {
	c, err := protocol.VerifyCard(card)
	if err != nil {
		return c, "", err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	idx := -1
	for i, ec := range st.s.Codes {
		if now.Before(ec.Expires) && sameHash(code, ec.Hash) {
			idx = i
		}
	}
	if idx < 0 {
		return c, "", errors.New("enrollment code unknown, used or expired")
	}
	st.s.Codes = append(st.s.Codes[:idx], st.s.Codes[idx+1:]...)
	if d, ok := st.s.Devices[c.DeviceID]; ok && !d.Revoked {
		_ = st.commit() // the code is spent either way
		return c, "", ErrConflict
	}
	tok, h := NewSecret()
	st.s.Devices[c.DeviceID] = &Device{ID: c.DeviceID, Name: c.Name, Card: card, TokenHash: h, EnrolledAt: now}
	return c, tok, st.commit()
}

func (st *Store) DeviceByToken(tok string, now time.Time) (*Device, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, d := range st.s.Devices {
		if !d.Revoked && sameHash(tok, d.TokenHash) {
			if now.Sub(d.LastSeen) > time.Minute {
				d.LastSeen = now
				_ = st.commit()
			}
			c := *d
			return &c, true
		}
	}
	return nil, false
}

// RevokeDevice stops the hub talking to a device. Adapters must also drop it from their trust list: the hub cannot
// do that for them, by design.
func (st *Store) RevokeDevice(id string) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	d, ok := st.s.Devices[id]
	if !ok {
		return ErrUnknown
	}
	d.Revoked = true
	d.TokenHash = ""
	return st.commit()
}

func (st *Store) Devices() []Device {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Device, 0, len(st.s.Devices))
	for _, d := range st.s.Devices {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EnrolledAt.Before(out[j].EnrolledAt) })
	return out
}

func (st *Store) Device(id string) (Device, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	d, ok := st.s.Devices[id]
	if !ok {
		return Device{}, false
	}
	return *d, true
}

// ---- requests, decisions, acks ----

func rkey(adapter, id string) string { return adapter + "/" + id }

// Publish stores a request an adapter sealed for its devices.
func (st *Store) Publish(adapter string, r Request, now time.Time) error {
	if r.ID == "" || len(r.ID) > 128 || len(r.Boxes) == 0 {
		return errors.New("request needs an id (≤128 chars) and at least one box")
	}
	size := 0
	for _, b := range r.Boxes {
		size += len(b.CT) + len(b.Enc)
	}
	if size > MaxBoxBytes {
		return errors.New("boxes too large")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.gc(now)
	k := rkey(adapter, r.ID)
	if _, ok := st.s.Requests[k]; ok {
		return ErrConflict
	}
	n := 0
	for _, x := range st.s.Requests {
		if x.Adapter == adapter && x.Ack == nil {
			n++
		}
	}
	if n >= MaxPendingPerAdapter {
		return ErrTooMany
	}
	r.Adapter, r.Ack, r.ResolvedAt, r.Decisions = adapter, nil, time.Time{}, 0
	st.s.Requests[k] = &r
	return st.commit()
}

// ForDevice lists unresolved, unexpired requests that carry a box for the device.
func (st *Store) ForDevice(deviceID string, now time.Time) []Request {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []Request
	for _, r := range st.s.Requests {
		if _, ok := r.Boxes[deviceID]; ok && r.Ack == nil && now.Unix() <= r.ExpiresAt {
			out = append(out, Request{Adapter: r.Adapter, ID: r.ID, Kind: r.Kind, CreatedAt: r.CreatedAt,
				ExpiresAt: r.ExpiresAt, Boxes: map[string]protocol.Sealed{deviceID: r.Boxes[deviceID]}})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// Decide queues a device's decision for the adapter. The hub does not (and cannot meaningfully) judge it.
func (st *Store) Decide(deviceID, adapter, requestID string, d protocol.Envelope, now time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	r, ok := st.s.Requests[rkey(adapter, requestID)]
	if !ok || r.Ack != nil {
		return ErrUnknown
	}
	if _, ok := r.Boxes[deviceID]; !ok {
		return ErrUnknown
	}
	if len(st.s.Decisions) >= MaxDecisionsQueued {
		return errors.New("decision queue full")
	}
	r.Decisions++
	st.s.Decisions = append(st.s.Decisions, QueuedDecision{Adapter: adapter, RequestID: requestID, DeviceID: deviceID, Decision: d, At: now})
	return st.commit()
}

// TakeDecisions removes and returns the decisions queued for an adapter.
func (st *Store) TakeDecisions(adapter string) []QueuedDecision {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []QueuedDecision
	keep := st.s.Decisions[:0]
	for _, d := range st.s.Decisions {
		if d.Adapter == adapter {
			out = append(out, d)
		} else {
			keep = append(keep, d)
		}
	}
	if len(out) == 0 {
		return nil
	}
	st.s.Decisions = keep
	_ = st.commit()
	return out
}

// Final reports whether an outcome ends a request. Rejected (the decision did not verify) and failed (the service
// call failed) leave it pending, so the person can decide again.
func Final(outcome string) bool {
	return outcome == protocol.OutcomeApproved || outcome == protocol.OutcomeDenied || outcome == protocol.OutcomeExpired
}

// Ack records the adapter's signed outcome. A final one stops the request being offered to devices; any other is
// kept as a note (the last few per request) so the phone can say why nothing happened.
func (st *Store) Ack(adapter, requestID, outcome string, ack protocol.Envelope, now time.Time) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	r, ok := st.s.Requests[rkey(adapter, requestID)]
	if !ok {
		return ErrUnknown
	}
	if !Final(outcome) {
		r.Notes = append(r.Notes, Note{Ack: ack, At: now})
		if len(r.Notes) > 5 {
			r.Notes = r.Notes[len(r.Notes)-5:]
		}
		return st.commit()
	}
	r.Ack, r.ResolvedAt = &ack, now
	r.Boxes = nil // nothing left to decide; drop the ciphertexts
	return st.commit()
}

type Note struct {
	Ack protocol.Envelope `json:"ack"`
	At  time.Time         `json:"at"`
}

type AckEntry struct {
	Adapter   string            `json:"adapter"`
	RequestID string            `json:"request_id"`
	Ack       protocol.Envelope `json:"ack"`
	At        time.Time         `json:"-"`
}

// Acks lists acks and notes from since on. Acks are signed, not secret; every device may read them.
func (st *Store) Acks(since time.Time) []AckEntry {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []AckEntry
	for _, r := range st.s.Requests {
		for _, n := range r.Notes {
			if !n.At.Before(since) {
				out = append(out, AckEntry{Adapter: r.Adapter, RequestID: r.ID, Ack: n.Ack, At: n.At})
			}
		}
		if r.Ack != nil && !r.ResolvedAt.Before(since) {
			out = append(out, AckEntry{Adapter: r.Adapter, RequestID: r.ID, Ack: *r.Ack, At: r.ResolvedAt})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

// Requests lists everything the hub holds, for the management UI: metadata only.
func (st *Store) Requests() []Request {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]Request, 0, len(st.s.Requests))
	for _, r := range st.s.Requests {
		c := *r
		c.Boxes = nil
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

// gc drops resolved requests after KeepResolved and expired unresolved ones after the same grace. mu held.
func (st *Store) gc(now time.Time) {
	for k, r := range st.s.Requests {
		switch {
		case r.Ack != nil && now.Sub(r.ResolvedAt) > KeepResolved:
			delete(st.s.Requests, k)
		case r.Ack == nil && now.Sub(time.Unix(r.ExpiresAt, 0)) > KeepResolved:
			delete(st.s.Requests, k)
		}
	}
}

func validID(s string) bool {
	if len(s) == 0 || len(s) > 40 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Path is the state file.
func (st *Store) Path() string { return st.path }
