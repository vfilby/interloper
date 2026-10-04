package adapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"warpgate-approver/broker/internal/protocol"
)

// Trust is the adapter's own list of devices it will send requests to and take decisions from: device cards added
// by the admin on this host (`wga-adapter trust add`). The hub's device list is never consulted.
type Trust struct {
	path    string
	modTime time.Time
	cards   map[string]protocol.DeviceCard
}

func LoadTrust(path string) (*Trust, error) {
	t := &Trust{path: path, cards: map[string]protocol.DeviceCard{}}
	return t, t.reload(true)
}

// Reload rereads the file if it changed, so `trust remove` takes effect without a restart.
func (t *Trust) Reload() error { return t.reload(false) }

func (t *Trust) reload(force bool) error {
	fi, err := os.Stat(t.path)
	if errors.Is(err, os.ErrNotExist) {
		t.cards, t.modTime = map[string]protocol.DeviceCard{}, time.Time{}
		return nil
	}
	if err != nil {
		return err
	}
	if !force && fi.ModTime().Equal(t.modTime) {
		return nil
	}
	envs, err := readCards(t.path)
	if err != nil {
		return err
	}
	cards := map[string]protocol.DeviceCard{}
	for _, e := range envs {
		c, err := protocol.VerifyCard(e)
		if err != nil {
			return fmt.Errorf("%s: %w", t.path, err) // a bad file must not silently shrink or grow the list
		}
		cards[c.DeviceID] = c
	}
	t.cards, t.modTime = cards, fi.ModTime()
	return nil
}

func (t *Trust) Card(id string) (protocol.DeviceCard, bool) {
	c, ok := t.cards[id]
	return c, ok
}

func (t *Trust) Cards() []protocol.DeviceCard {
	out := make([]protocol.DeviceCard, 0, len(t.cards))
	for _, c := range t.cards {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

func readCards(path string) ([]protocol.Envelope, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var envs []protocol.Envelope
	if err := json.Unmarshal(b, &envs); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return envs, nil
}

func writeCards(path string, envs []protocol.Envelope) error {
	b, err := json.MarshalIndent(envs, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// TrustAdd verifies a card and adds it to the trust file. It returns the card so the caller can print the fingerprint
// for the admin to compare with the phone.
func TrustAdd(path string, card protocol.Envelope) (protocol.DeviceCard, error) {
	c, err := protocol.VerifyCard(card)
	if err != nil {
		return c, err
	}
	envs, err := readCards(path)
	if err != nil {
		return c, err
	}
	for _, e := range envs {
		if e.Kid == c.DeviceID {
			return c, fmt.Errorf("device %s is already trusted", c.DeviceID)
		}
	}
	return c, writeCards(path, append(envs, card))
}

// TrustRemove drops a device from the trust file.
func TrustRemove(path, id string) error {
	envs, err := readCards(path)
	if err != nil {
		return err
	}
	keep := envs[:0]
	for _, e := range envs {
		if e.Kid != id {
			keep = append(keep, e)
		}
	}
	if len(keep) == len(envs) {
		return fmt.Errorf("device %s is not trusted", id)
	}
	return writeCards(path, keep)
}
