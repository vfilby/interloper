package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"warpgate-approver/broker/internal/protocol"
)

// Pin is a user this adapter trusts: their id and account fingerprint (the hash of their genesis roster).
type Pin struct {
	User    string `json:"user"`
	Account string `json:"account"`
}

// Trust is the adapter's own view of who may approve: pinned users (trusted-users.json, written by
// `wga-adapter trust add-user`) and, for each, the newest roster chain it has verified back to the pin
// (trusted-heads.json). Chains come through the hub, but nothing about them is taken on the hub's word: a chain must
// verify against the pin, and a verified head is never replaced by an older or a different one at the same seq.
type Trust struct {
	mu                  sync.RWMutex // the poll loop refreshes while the decision loop reads
	pinsPath, headsPath string
	modTime             time.Time
	pins                []Pin
	chains              map[string][]protocol.Envelope // user -> newest verified chain
	heads               map[string]protocol.Head
}

const (
	pinsFile  = "trusted-users.json"
	headsFile = "trusted-heads.json"
)

func LoadTrust(dir string) (*Trust, error) {
	t := &Trust{pinsPath: filepath.Join(dir, pinsFile), headsPath: filepath.Join(dir, headsFile),
		chains: map[string][]protocol.Envelope{}, heads: map[string]protocol.Head{}}
	if err := t.reload(true); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(t.headsPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		var saved map[string][]protocol.Envelope
		if err := json.Unmarshal(b, &saved); err != nil {
			return nil, fmt.Errorf("%s: %w", t.headsPath, err)
		}
		for _, p := range t.pins {
			if ch, ok := saved[p.User]; ok {
				h, err := protocol.VerifyChain(ch, p.User, p.Account)
				if err != nil {
					return nil, fmt.Errorf("%s: saved chain for %s: %w", t.headsPath, p.User, err)
				}
				t.chains[p.User], t.heads[p.User] = ch, h
			}
		}
	}
	return t, nil
}

// Reload rereads the pins if the file changed, so `trust add-user` / `remove-user` take effect without a restart.
func (t *Trust) Reload() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reload(false)
}

func (t *Trust) reload(force bool) error {
	fi, err := os.Stat(t.pinsPath)
	if errors.Is(err, os.ErrNotExist) {
		t.pins, t.modTime = nil, time.Time{}
		t.prune()
		return nil
	}
	if err != nil {
		return err
	}
	if !force && fi.ModTime().Equal(t.modTime) {
		return nil
	}
	pins, err := readPins(t.pinsPath)
	if err != nil {
		return err // a bad file must not silently change who is trusted
	}
	t.pins, t.modTime = pins, fi.ModTime()
	t.prune()
	return nil
}

// prune forgets chains of users no longer pinned, or pinned to another account.
func (t *Trust) prune() {
	for u, h := range t.heads {
		keep := false
		for _, p := range t.pins {
			keep = keep || (p.User == u && p.Account == h.Account)
		}
		if !keep {
			delete(t.heads, u)
			delete(t.chains, u)
		}
	}
}

// Refresh fetches each pinned user's chain and adopts it if it verifies and is not older than what is known. It
// returns the problems found; users with a problem keep their last good head.
func (t *Trust) Refresh(ctx context.Context, fetch func(ctx context.Context, user string) ([]protocol.Envelope, error)) []error {
	t.mu.RLock()
	pins := append([]Pin(nil), t.pins...)
	t.mu.RUnlock()
	var errs []error
	changed := false
	for _, p := range pins {
		chain, err := fetch(ctx, p.User) // over the network: not under the lock
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: fetching roster: %w", p.User, err))
			continue
		}
		h, err := protocol.VerifyChain(chain, p.User, p.Account)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: roster does not verify: %w", p.User, err))
			continue
		}
		t.mu.Lock()
		old, known := t.heads[p.User]
		adopt := false
		switch {
		case !known:
			adopt = true
		case h.Roster.Seq > old.Roster.Seq && !extendsHead(chain, old):
			// A longer chain that branches off before the head already seen: e.g. a device removed in that head signing
			// an alternative history from a roster it was still on. Adopting it would undo the removal.
			errs = append(errs, fmt.Errorf("%s: hub offers roster v%d that does not build on v%d already seen: ignored", p.User, h.Roster.Seq, old.Roster.Seq))
		case h.Roster.Seq > old.Roster.Seq:
			adopt = true
		case h.Roster.Seq < old.Roster.Seq:
			errs = append(errs, fmt.Errorf("%s: hub offers roster v%d, older than v%d already seen: ignored", p.User, h.Roster.Seq, old.Roster.Seq))
		case string(h.Payload) != string(old.Payload):
			errs = append(errs, fmt.Errorf("%s: hub offers a different roster v%d than the one already seen: ignored", p.User, h.Roster.Seq))
		}
		// The pin may have changed while fetching; adopt only for the pin still in force.
		if adopt && t.pinned(p) {
			t.chains[p.User], t.heads[p.User] = chain, h
			changed = true
		}
		t.mu.Unlock()
	}
	if changed {
		t.mu.RLock()
		err := t.save()
		t.mu.RUnlock()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (t *Trust) save() error {
	b, err := json.Marshal(t.chains)
	if err != nil {
		return err
	}
	tmp := t.headsPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, t.headsPath)
}

// extendsHead reports whether chain contains, at the head's position, exactly the head already verified.
func extendsHead(chain []protocol.Envelope, head protocol.Head) bool {
	i := head.Roster.Seq - 1
	if i >= len(chain) {
		return false
	}
	p, err := chain[i].PayloadBytes()
	return err == nil && string(p) == string(head.Payload)
}

func (t *Trust) pinned(p Pin) bool {
	for _, q := range t.pins {
		if q == p {
			return true
		}
	}
	return false
}

// Card finds a device on a trusted user's current roster, and that user.
func (t *Trust) Card(id string) (protocol.DeviceCard, string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for u, h := range t.heads {
		if c, ok := h.Devices[id]; ok {
			return c, u, true
		}
	}
	return protocol.DeviceCard{}, "", false
}

// Cards lists every device on a trusted user's current roster.
func (t *Trust) Cards() []protocol.DeviceCard {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []protocol.DeviceCard
	for _, h := range t.heads {
		for _, c := range h.Devices {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

// Pins lists the trusted users with their current head (zero Head if none verified yet).
func (t *Trust) Pins() ([]Pin, map[string]protocol.Head) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	heads := make(map[string]protocol.Head, len(t.heads))
	for u, h := range t.heads {
		heads[u] = h
	}
	return append([]Pin(nil), t.pins...), heads
}

func readPins(path string) ([]Pin, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pins []Pin
	if err := json.Unmarshal(b, &pins); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, p := range pins {
		if !protocol.ValidUserID(p.User) || len(p.Account) != 39 {
			return nil, fmt.Errorf("%s: bad pin %+v", path, p)
		}
	}
	return pins, nil
}

func writePins(path string, pins []Pin) error {
	b, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// TrustAddUser pins a user by account fingerprint (from their first phone, or the hub's user list).
func TrustAddUser(dir, user, account string) error {
	if !protocol.ValidUserID(user) || len(account) != 39 {
		return errors.New("want a user id and an account fingerprint like 3f2a-91c0-77de-0b14-5c2e-aa01-9d3b-71f0")
	}
	path := filepath.Join(dir, pinsFile)
	pins, err := readPins(path)
	if err != nil {
		return err
	}
	for _, p := range pins {
		if p.User == user {
			return fmt.Errorf("user %s is already trusted (account %s); remove-user first to change it", user, p.Account)
		}
	}
	return writePins(path, append(pins, Pin{User: user, Account: account}))
}

// TrustRemoveUser stops trusting a user.
func TrustRemoveUser(dir, user string) error {
	path := filepath.Join(dir, pinsFile)
	pins, err := readPins(path)
	if err != nil {
		return err
	}
	keep := pins[:0]
	for _, p := range pins {
		if p.User != user {
			keep = append(keep, p)
		}
	}
	if len(keep) == len(pins) {
		return fmt.Errorf("user %s is not trusted", user)
	}
	return writePins(path, keep)
}
