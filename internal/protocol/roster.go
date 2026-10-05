package protocol

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

const MemberDevice = "device"

type Member struct {
	Kind string   `json:"kind"`
	Card Envelope `json:"card"`
}

// Roster is one version of a user's device list (docs/PROTOCOL.md, "Users and rosters").
type Roster struct {
	V       int      `json:"v"`
	User    string   `json:"user"`
	Seq     int      `json:"seq"`
	Prev    string   `json:"prev"`
	Members []Member `json:"members"`
	TS      int64    `json:"ts"`
}

// Head is a verified chain's newest roster with its devices.
type Head struct {
	Roster  Roster
	Payload []byte                // exact bytes of the head roster; the next roster's prev hashes these
	Devices map[string]DeviceCard // by device id
	Account string                // account fingerprint (from r1)
}

// AccountFingerprint is the first 16 bytes of SHA-256 over the genesis roster's payload, as 8 groups of 4 hex digits.
func AccountFingerprint(genesisPayload []byte) string {
	h := hex.EncodeToString(Hash(genesisPayload)[:16])
	out := h[0:4]
	for i := 4; i < len(h); i += 4 {
		out += "-" + h[i:i+4]
	}
	return out
}

// ValidUserID reports whether s is a user id: 1-40 of a-z 0-9 . _ -.
func ValidUserID(s string) bool {
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

// parseRoster decodes a roster payload and checks what can be checked without its signer: shape and member cards.
func parseRoster(p []byte) (Roster, map[string]DeviceCard, error) {
	var r Roster
	if err := json.Unmarshal(p, &r); err != nil {
		return r, nil, fmt.Errorf("roster: %w", err)
	}
	if r.V != Version || !ValidUserID(r.User) || r.Seq < 1 || len(r.Members) == 0 {
		return r, nil, errors.New("roster: bad version, user, seq or empty members")
	}
	devs := map[string]DeviceCard{}
	for _, m := range r.Members {
		if m.Kind != MemberDevice {
			return r, nil, fmt.Errorf("roster: unknown member kind %q", m.Kind)
		}
		c, err := VerifyCard(m.Card)
		if err != nil {
			return r, nil, fmt.Errorf("roster member: %w", err)
		}
		if _, dup := devs[c.DeviceID]; dup {
			return r, nil, fmt.Errorf("roster: device %s listed twice", c.DeviceID)
		}
		devs[c.DeviceID] = c
	}
	return r, devs, nil
}

// signedBy checks that e is signed by the approve key of one of devs.
func signedBy(e Envelope, devs map[string]DeviceCard) ([]byte, error) {
	c, ok := devs[e.Kid]
	if !ok {
		return nil, fmt.Errorf("roster signed by %s, which is not a member of the roster it must be signed under", e.Kid)
	}
	ak, _ := UnB64(c.ApproveKey)
	p, err := VerifyES256(e, ak)
	if err != nil {
		return nil, fmt.Errorf("roster signature: %w", err)
	}
	return p, nil
}

// VerifyChain checks a whole chain against a pinned user and account fingerprint and returns its head.
// account "" skips the pin check (the hub, and a device on first sight, which then pins what it saw).
func VerifyChain(chain []Envelope, user, account string) (Head, error) {
	if len(chain) == 0 {
		return Head{}, errors.New("empty roster chain")
	}
	// Genesis: signed by one of its own members.
	gp, err := UnB64(chain[0].Payload)
	if err != nil {
		return Head{}, err
	}
	r, devs, err := parseRoster(gp)
	if err != nil {
		return Head{}, err
	}
	if _, err := signedBy(chain[0], devs); err != nil {
		return Head{}, fmt.Errorf("genesis: %w", err)
	}
	if r.Seq != 1 || r.Prev != "" || r.User != user {
		return Head{}, errors.New("genesis: must be seq 1, no prev, and for this user")
	}
	acct := AccountFingerprint(gp)
	if account != "" && acct != account {
		return Head{}, fmt.Errorf("account fingerprint %s does not match the pinned %s", acct, account)
	}
	head := Head{Roster: r, Payload: gp, Devices: devs, Account: acct}
	for _, e := range chain[1:] {
		if head, err = Extend(head, e); err != nil {
			return Head{}, err
		}
	}
	return head, nil
}

// Extend checks that e is the next roster after head and returns the new head.
func Extend(head Head, e Envelope) (Head, error) {
	p, err := signedBy(e, head.Devices) // signed under the previous roster
	if err != nil {
		return Head{}, fmt.Errorf("roster %d: %w", head.Roster.Seq+1, err)
	}
	r, devs, err := parseRoster(p)
	if err != nil {
		return Head{}, err
	}
	switch {
	case r.User != head.Roster.User:
		return Head{}, errors.New("roster changes user")
	case r.Seq != head.Roster.Seq+1:
		return Head{}, fmt.Errorf("roster seq %d after %d", r.Seq, head.Roster.Seq)
	case r.Prev != B64(Hash(head.Payload)):
		return Head{}, fmt.Errorf("roster %d does not follow roster %d", r.Seq, head.Roster.Seq)
	}
	return Head{Roster: r, Payload: p, Devices: devs, Account: head.Account}, nil
}

// NextRoster builds (unsigned) the roster after head with the given member cards, signed later by a current member.
func NextRoster(head Head, members []Envelope, ts int64) Roster {
	r := Roster{V: Version, User: head.Roster.User, Seq: head.Roster.Seq + 1, Prev: B64(Hash(head.Payload)), TS: ts}
	for _, c := range members {
		r.Members = append(r.Members, Member{Kind: MemberDevice, Card: c})
	}
	return r
}

// SignRoster signs a roster with a device's approve key.
func SignRoster(approve *ecdsa.PrivateKey, deviceID string, r Roster) (Envelope, error) {
	return SignES256(approve, deviceID, r)
}

// Cards returns the head's member card envelopes, in roster order.
func (h Head) Cards() []Envelope {
	out := make([]Envelope, 0, len(h.Roster.Members))
	for _, m := range h.Roster.Members {
		out = append(out, m.Card)
	}
	return out
}
