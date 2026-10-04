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
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Card          protocol.Envelope `json:"card"`
	TokenHash     string            `json:"token_hash"`
	EnrolledAt    time.Time         `json:"enrolled_at"`
	LastSeen      time.Time         `json:"last_seen,omitzero"`
	Revoked       bool              `json:"revoked,omitempty"`
	User          string            `json:"user,omitempty"`           // "" only for devices enrolled before accounts existed
	JoinRequested bool              `json:"join_requested,omitempty"` // enrolled with a join code, not yet in the user's roster
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
	Device  string    `json:"device,omitempty"` // set once spent: who enrolled with it (for the enroll page)
	User    string    `json:"user"`
	Mode    string    `json:"mode"`
}

// codeID names a code in URLs without revealing it: a prefix of the hash the hub keeps anyway.
func codeID(hash string) string { return hash[:16] }

type state struct {
	Adapters  map[string]*Adapter `json:"adapters"`
	Devices   map[string]*Device  `json:"devices"`
	Requests  map[string]*Request `json:"requests"` // adapter + "/" + id
	Decisions []QueuedDecision    `json:"decisions"`
	Codes     []enrollCode        `json:"codes"`
	Users     map[string]*User    `json:"users"`
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
		s: state{Adapters: map[string]*Adapter{}, Devices: map[string]*Device{}, Requests: map[string]*Request{}, Users: map[string]*User{}}}
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
		if st.s.Users == nil {
			st.s.Users = map[string]*User{}
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

// ---- users, devices, enrollment ----

const (
	ModeNew  = "new"  // the code makes the first device of a new user, which brings the user's genesis roster
	ModeJoin = "join" // the code adds a device to an existing user, pending approval on one of the user's devices
)

// User is an account: its roster chain, as posted by its devices. The hub checks each roster extends the chain so
// it does not store garbage, but nothing trusts the hub for that: adapters and devices verify the chain themselves.
type User struct {
	ID        string              `json:"id"`
	Chain     []protocol.Envelope `json:"chain"`
	CreatedAt time.Time           `json:"created_at"`
}

// UserView is a user with its verified head, for the UI and the API.
type UserView struct {
	User
	Head    protocol.Head
	Pending []Device // devices that enrolled with a join code and are not in the head yet
}

func (st *Store) head(u *User) (protocol.Head, error) {
	return protocol.VerifyChain(u.Chain, u.ID, "")
}

// NewEnrollCode returns a one-time enrollment code for a user and mode, and an id for following it (EnrollStatus).
func (st *Store) NewEnrollCode(now time.Time, user, mode string) (code, id string, err error) {
	if !protocol.ValidUserID(user) {
		return "", "", errors.New("user id: 1-40 of a-z 0-9 . _ -")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	_, exists := st.s.Users[user]
	switch {
	case mode == ModeNew && exists:
		return "", "", fmt.Errorf("user %s exists: add a device to it instead", user)
	case mode == ModeJoin && !exists:
		return "", "", fmt.Errorf("no user %s: create it first", user)
	case mode != ModeNew && mode != ModeJoin:
		return "", "", fmt.Errorf("mode %q", mode)
	}
	code, h := NewSecret()
	keep := st.s.Codes[:0]
	open := 0
	for _, c := range st.s.Codes {
		// Spent codes are kept a while after expiry so the enroll page can still say who used them.
		if now.Before(c.Expires.Add(time.Hour)) {
			keep = append(keep, c)
			if c.Device == "" && now.Before(c.Expires) {
				open++
			}
		}
	}
	st.s.Codes = keep
	if open >= 10 {
		return "", "", errors.New("too many open enrollment codes; wait for them to expire")
	}
	st.s.Codes = append(st.s.Codes, enrollCode{Hash: h, Expires: now.Add(EnrollCodeTTL), User: user, Mode: mode})
	return code, codeID(h), st.commit()
}

// EnrollStatus reports on a code by id.
type EnrollStatus struct {
	Expires time.Time
	User    string
	Mode    string
	Device  string // "" while unused
}

func (st *Store) EnrollStatus(id string) (EnrollStatus, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, c := range st.s.Codes {
		if codeID(c.Hash) == id {
			return EnrollStatus{Expires: c.Expires, User: c.User, Mode: c.Mode, Device: c.Device}, true
		}
	}
	return EnrollStatus{}, false
}

// Enrolled is the outcome of Enroll.
type Enrolled struct {
	Card   protocol.DeviceCard
	Token  string
	User   string
	Active bool // in the user's head roster; false: a join waiting for approval
}

// Enroll spends a code and registers the device. A `new` code needs the user's genesis roster, containing this card
// and signed by it; a `join` code must come without one. A device already in the user's head (it left this hub, or
// the hub was reset) is simply active again: the code is admin-issued and the card is signed by the same key.
func (st *Store) Enroll(code string, card protocol.Envelope, genesis *protocol.Envelope, now time.Time) (Enrolled, error) {
	c, err := protocol.VerifyCard(card)
	if err != nil {
		return Enrolled{}, err
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	idx := -1
	for i, ec := range st.s.Codes {
		if ec.Device == "" && now.Before(ec.Expires) && sameHash(code, ec.Hash) {
			idx = i
		}
	}
	if idx < 0 {
		return Enrolled{}, errors.New("enrollment code unknown, used or expired")
	}
	ec := st.s.Codes[idx]
	if d, ok := st.s.Devices[c.DeviceID]; ok && d.User != "" && d.User != ec.User {
		return Enrolled{}, fmt.Errorf("this device belongs to user %s", d.User)
	}

	out := Enrolled{Card: c, User: ec.User}
	switch ec.Mode {
	case ModeNew:
		if genesis == nil {
			return Enrolled{}, errors.New("a new-user code needs the genesis roster")
		}
		if _, ok := st.s.Users[ec.User]; ok {
			return Enrolled{}, fmt.Errorf("user %s exists", ec.User)
		}
		h, err := protocol.VerifyChain([]protocol.Envelope{*genesis}, ec.User, "")
		if err != nil {
			return Enrolled{}, err
		}
		if _, ok := h.Devices[c.DeviceID]; !ok || genesis.Kid != c.DeviceID {
			return Enrolled{}, errors.New("the genesis roster must contain and be signed by the enrolling device")
		}
		st.s.Users[ec.User] = &User{ID: ec.User, Chain: []protocol.Envelope{*genesis}, CreatedAt: now}
		out.Active = true
	case ModeJoin:
		if genesis != nil {
			return Enrolled{}, errors.New("a join code takes no genesis roster")
		}
		u, ok := st.s.Users[ec.User]
		if !ok {
			return Enrolled{}, fmt.Errorf("no user %s", ec.User)
		}
		h, err := st.head(u)
		if err != nil {
			return Enrolled{}, err
		}
		_, out.Active = h.Devices[c.DeviceID]
	}

	st.s.Codes[idx].Device = c.DeviceID // spent
	tok, th := NewSecret()
	out.Token = tok
	st.s.Devices[c.DeviceID] = &Device{ID: c.DeviceID, Name: c.Name, Card: card, TokenHash: th, EnrolledAt: now,
		User: ec.User, JoinRequested: !out.Active}
	return out, st.commit()
}

// Chain returns a user's roster chain.
func (st *Store) Chain(user string) ([]protocol.Envelope, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	u, ok := st.s.Users[user]
	if !ok {
		return nil, false
	}
	return append([]protocol.Envelope(nil), u.Chain...), true
}

// AppendRoster adds the next roster to a user's chain if it extends it. Devices it drops stop being served (their
// tokens are cleared); devices it adds stop being join requests.
func (st *Store) AppendRoster(user string, r protocol.Envelope) (protocol.Head, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	u, ok := st.s.Users[user]
	if !ok {
		return protocol.Head{}, ErrUnknown
	}
	old, err := st.head(u)
	if err != nil {
		return protocol.Head{}, err
	}
	h, err := protocol.Extend(old, r)
	if err != nil {
		return protocol.Head{}, err
	}
	u.Chain = append(u.Chain, r)
	for id := range old.Devices {
		if _, still := h.Devices[id]; !still {
			if d, ok := st.s.Devices[id]; ok {
				d.Revoked, d.TokenHash = true, ""
			}
		}
	}
	for id := range h.Devices {
		if d, ok := st.s.Devices[id]; ok {
			d.JoinRequested = false
		}
	}
	return h, st.commit()
}

// Users lists accounts with their verified heads and pending joins.
func (st *Store) Users() []UserView {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]UserView, 0, len(st.s.Users))
	for _, u := range st.s.Users {
		v := UserView{User: *u}
		v.Head, _ = st.head(u) // a chain the hub accepted verifies; a zero head shows as broken in the UI
		for _, d := range st.s.Devices {
			if d.User == u.ID && d.JoinRequested && !d.Revoked {
				v.Pending = append(v.Pending, *d)
			}
		}
		sort.Slice(v.Pending, func(i, j int) bool { return v.Pending[i].EnrolledAt.Before(v.Pending[j].EnrolledAt) })
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Joins lists a user's pending join requests.
func (st *Store) Joins(user string) []Device {
	for _, u := range st.Users() {
		if u.ID == user {
			return u.Pending
		}
	}
	return nil
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

// DeleteUser forgets an account: its roster, its devices and its unused codes. It is the way out when no phone on
// the roster is left to approve another (all lost or revoked): the next enrollment for the user starts a new account,
// with a new account fingerprint that adapters must trust again. It returns the ids of the devices it removed.
func (st *Store) DeleteUser(id string) ([]string, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if _, ok := st.s.Users[id]; !ok {
		return nil, ErrUnknown
	}
	gone := st.deleteUser(id)
	return gone, st.commit()
}

// deleteUser drops a user, its devices and its codes. Callers hold the lock and commit.
func (st *Store) deleteUser(id string) []string {
	delete(st.s.Users, id)
	var gone []string
	for did, d := range st.s.Devices {
		if d.User == id {
			gone = append(gone, did)
		}
	}
	st.dropDevices(gone)
	codes := st.s.Codes[:0]
	for _, c := range st.s.Codes {
		if c.User != id {
			codes = append(codes, c)
		}
	}
	st.s.Codes = codes
	sort.Strings(gone)
	return gone
}

// Leave is a device going away from the hub, at its own request (its token). What happens to the account:
//   - roster set: the next roster, signed by a member, without this device (a phone resetting its keys takes itself
//     off the account first). The hub appends it, as for any roster.
//   - deleteAccount: this device is the account's only member and its keys are going: nothing could ever sign the
//     account's next roster, so the account goes too (DeleteUser).
//   - neither: the roster stays as it is (a device that keeps its keys may come back with a join code; one that is
//     not a member loses nothing).
//
// The device record goes in every case. It returns whether the account was deleted.
func (st *Store) Leave(deviceID string, roster *protocol.Envelope, deleteAccount bool) (bool, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	d, ok := st.s.Devices[deviceID]
	if !ok {
		return false, ErrUnknown
	}
	u := st.s.Users[d.User]
	switch {
	case roster != nil && deleteAccount:
		return false, errors.New("leave: a roster or deleting the account, not both")
	case (roster != nil || deleteAccount) && u == nil:
		return false, errors.New("leave: the device has no account")
	case roster != nil:
		old, err := st.head(u)
		if err != nil {
			return false, err
		}
		h, err := protocol.Extend(old, *roster)
		if err != nil {
			return false, err
		}
		if _, still := h.Devices[deviceID]; still {
			return false, errors.New("leave: the roster still has this device")
		}
		u.Chain = append(u.Chain, *roster)
		for id := range old.Devices {
			if _, still := h.Devices[id]; !still && id != deviceID {
				if o, ok := st.s.Devices[id]; ok {
					o.Revoked, o.TokenHash = true, ""
				}
			}
		}
	case deleteAccount:
		h, err := st.head(u)
		if err != nil {
			return false, err
		}
		if _, member := h.Devices[deviceID]; !member || len(h.Devices) != 1 {
			return false, errors.New("leave: only an account's last device may delete it; remove this device from the roster instead")
		}
		st.deleteUser(u.ID)
		return true, st.commit()
	}
	st.dropDevices([]string{deviceID})
	return false, st.commit()
}

// RemoveRevokedDevices deletes the devices revoked at the hub, which are otherwise kept (and listed) for reference.
// It returns the ids it removed.
func (st *Store) RemoveRevokedDevices() ([]string, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	var gone []string
	for did, d := range st.s.Devices {
		if d.Revoked {
			gone = append(gone, did)
		}
	}
	if len(gone) == 0 {
		return nil, nil
	}
	st.dropDevices(gone)
	sort.Strings(gone)
	return gone, st.commit()
}

// dropDevices deletes devices with what the hub holds for them: their sealed copies of requests and their queued
// decisions. Callers hold the lock and commit.
func (st *Store) dropDevices(ids []string) {
	if len(ids) == 0 {
		return
	}
	drop := make(map[string]bool, len(ids))
	for _, id := range ids {
		drop[id] = true
		delete(st.s.Devices, id)
	}
	for _, r := range st.s.Requests {
		for id := range drop {
			delete(r.Boxes, id)
		}
	}
	decisions := st.s.Decisions[:0]
	for _, q := range st.s.Decisions {
		if !drop[q.DeviceID] {
			decisions = append(decisions, q)
		}
	}
	st.s.Decisions = decisions
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

// ForceChain replaces a user's chain without checking it. Only for tests that play a hostile hub.
func (st *Store) ForceChain(user string, chain []protocol.Envelope) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if u, ok := st.s.Users[user]; ok {
		u.Chain = chain
		_ = st.commit()
	}
}
