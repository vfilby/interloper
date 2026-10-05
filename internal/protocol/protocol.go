// Package protocol is the wire format shared by adapters, the hub and the iOS app: docs/PROTOCOL.md, v1.
//
// Signatures cover the exact payload bytes carried in an envelope; nothing is canonicalized. Verify first, then
// parse: a payload is never looked at before its signature has been checked against a pinned key.
package protocol

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

const Version = 1

// MaxSkew is how far a decision's timestamp may be from the adapter's clock.
const MaxSkew = 5 * time.Minute

const (
	AlgEd25519 = "ed25519"
	AlgES256   = "es256"
)

var b64 = base64.RawURLEncoding

// B64 encodes as the protocol does everywhere: base64url, no padding.
func B64(b []byte) string { return b64.EncodeToString(b) }

// UnB64 decodes B64.
func UnB64(s string) ([]byte, error) { return b64.DecodeString(s) }

// Fingerprint is the first 8 bytes of SHA-256 over a raw public key, as 3f2a-91c0-77de-0b14.
func Fingerprint(raw []byte) string {
	h := hex.EncodeToString(Hash(raw)[:8])
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12] + "-" + h[12:16]
}

// DeviceID is the fingerprint of the approve key without dashes.
func DeviceID(approveKey []byte) string { return strings.ReplaceAll(Fingerprint(approveKey), "-", "") }

// Hash is SHA-256.
func Hash(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// Envelope is a signed payload.
type Envelope struct {
	Alg     string `json:"alg"`
	Kid     string `json:"kid"`
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

// PayloadBytes decodes the payload without verifying it: only for hashing an envelope already verified.
func (e Envelope) PayloadBytes() ([]byte, error) { return UnB64(e.Payload) }

// Sealed is an HPKE box addressed to one device.
type Sealed struct {
	Suite string `json:"suite"`
	Kid   string `json:"kid"`
	Enc   string `json:"enc"`
	CT    string `json:"ct"`
}

type Fact struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Level string `json:"level,omitempty"` // "", "warn", "danger"
}

type Principal struct {
	Principal  string `json:"principal"`
	Display    string `json:"display,omitempty"`
	AttestedBy string `json:"attested_by"`
}

type Lease struct {
	DurationS int64  `json:"duration_s"`
	Scope     string `json:"scope"`
	MaxUses   int    `json:"max_uses,omitempty"`
}

const (
	ShapeOnce  = "once"
	ShapeLease = "lease"

	RiskNormal   = "normal"
	RiskElevated = "elevated"
	RiskHigh     = "high"
)

// Record is what the person is asked to decide on.
type Record struct {
	V          int        `json:"v"`
	ID         string     `json:"id"`
	Adapter    string     `json:"adapter"`
	Kind       string     `json:"kind"`
	Shape      string     `json:"shape"`
	Risk       string     `json:"risk"`
	Title      string     `json:"title"`
	Requester  string     `json:"requester"`
	OnBehalfOf *Principal `json:"on_behalf_of,omitempty"`
	Facts      []Fact     `json:"facts"`
	Reason     string     `json:"reason"`
	Lease      *Lease     `json:"lease,omitempty"`
	CreatedAt  int64      `json:"created_at"`
	ExpiresAt  int64      `json:"expires_at"`
	Nonce      string     `json:"nonce"`
}

const (
	Approve = "approve"
	Deny    = "deny"
)

type Decision struct {
	V          int    `json:"v"`
	RequestID  string `json:"request_id"`
	Adapter    string `json:"adapter"`
	Decision   string `json:"decision"`
	RecordHash string `json:"record_hash"`
	Nonce      string `json:"nonce"`
	DeviceID   string `json:"device_id"`
	TS         int64  `json:"ts"`
}

const (
	OutcomeApproved = "approved"
	OutcomeDenied   = "denied"
	OutcomeRejected = "rejected" // the decision failed verification; nothing was done
	OutcomeExpired  = "expired"
	OutcomeFailed   = "failed" // the decision was valid but the service call failed
)

type Ack struct {
	V            int    `json:"v"`
	RequestID    string `json:"request_id"`
	Adapter      string `json:"adapter"`
	Outcome      string `json:"outcome"`
	Detail       string `json:"detail,omitempty"`
	DecisionHash string `json:"decision_hash,omitempty"`
	TS           int64  `json:"ts"`
}

// DeviceCard is a device's public keys, signed with its approve key.
type DeviceCard struct {
	V          int    `json:"v"`
	DeviceID   string `json:"device_id"`
	Name       string `json:"name"`
	ApproveKey string `json:"approve_key"`
	DenyKey    string `json:"deny_key"`
	EncKey     string `json:"enc_key"`
	CreatedAt  int64  `json:"created_at"`
}

// NewRequestID returns 12 random bytes as hex: safe to type and to pass as a command-line argument (a base64url id
// can start with "-").
func NewRequestID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// NewNonce returns 16 random bytes, encoded.
func NewNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return B64(b)
}

// ---- signing ----

// SignEd25519 marshals v and signs it as kid.
func SignEd25519(key ed25519.PrivateKey, kid string, v any) (Envelope, error) {
	p, err := json.Marshal(v)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Alg: AlgEd25519, Kid: kid, Payload: B64(p), Sig: B64(ed25519.Sign(key, p))}, nil
}

// SignES256 marshals v and signs it with a P-256 key (raw r||s), as the device does.
func SignES256(key *ecdsa.PrivateKey, kid string, v any) (Envelope, error) {
	p, err := json.Marshal(v)
	if err != nil {
		return Envelope{}, err
	}
	h := sha256.Sum256(p)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return Envelope{}, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return Envelope{Alg: AlgES256, Kid: kid, Payload: B64(p), Sig: B64(sig)}, nil
}

// VerifyEd25519 checks e against pub and returns the payload bytes.
func VerifyEd25519(e Envelope, pub ed25519.PublicKey) ([]byte, error) {
	if e.Alg != AlgEd25519 {
		return nil, fmt.Errorf("envelope alg %q, want %s", e.Alg, AlgEd25519)
	}
	p, sig, err := decodeEnvelope(e)
	if err != nil {
		return nil, err
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, p, sig) {
		return nil, errors.New("bad signature")
	}
	return p, nil
}

// VerifyES256 checks e against an X9.63 P-256 public key and returns the payload bytes.
func VerifyES256(e Envelope, x963 []byte) ([]byte, error) {
	if e.Alg != AlgES256 {
		return nil, fmt.Errorf("envelope alg %q, want %s", e.Alg, AlgES256)
	}
	pub, err := ParseP256(x963)
	if err != nil {
		return nil, err
	}
	p, sig, err := decodeEnvelope(e)
	if err != nil {
		return nil, err
	}
	if len(sig) != 64 {
		return nil, errors.New("bad signature length")
	}
	h := sha256.Sum256(p)
	if !ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, errors.New("bad signature")
	}
	return p, nil
}

func decodeEnvelope(e Envelope) (payload, sig []byte, err error) {
	if payload, err = UnB64(e.Payload); err != nil {
		return nil, nil, errors.New("envelope payload is not base64url")
	}
	if sig, err = UnB64(e.Sig); err != nil {
		return nil, nil, errors.New("envelope signature is not base64url")
	}
	return payload, sig, nil
}

// ParseP256 parses an X9.63 uncompressed P-256 public key for ECDSA.
func ParseP256(x963 []byte) (*ecdsa.PublicKey, error) {
	pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), x963) // validates the point
	if err != nil {
		return nil, fmt.Errorf("bad P-256 key: %w", err)
	}
	return pk, nil
}

// ---- sealing ----

// Seal signs nothing: it encrypts an already-signed envelope to one device's encryption key.
func Seal(rnd io.Reader, deviceID string, encKey []byte, signed Envelope) (Sealed, error) {
	pk, err := ecdh.P256().NewPublicKey(encKey)
	if err != nil {
		return Sealed{}, fmt.Errorf("device %s: bad encryption key: %w", deviceID, err)
	}
	pt, err := json.Marshal(signed)
	if err != nil {
		return Sealed{}, err
	}
	enc, ct, err := hpkeSeal(rnd, pk, HPKEInfo, nil, pt)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{Suite: SuiteHPKE, Kid: deviceID, Enc: B64(enc), CT: B64(ct)}, nil
}

// Open decrypts a box with the device's encryption key and returns the signed envelope inside (not yet verified).
func Open(key *ecdh.PrivateKey, s Sealed) (Envelope, error) {
	if s.Suite != SuiteHPKE {
		return Envelope{}, fmt.Errorf("unknown suite %q", s.Suite)
	}
	enc, err := UnB64(s.Enc)
	if err != nil {
		return Envelope{}, err
	}
	ct, err := UnB64(s.CT)
	if err != nil {
		return Envelope{}, err
	}
	pt, err := hpkeOpen(key, enc, HPKEInfo, nil, ct)
	if err != nil {
		return Envelope{}, errors.New("box does not open")
	}
	var e Envelope
	return e, json.Unmarshal(pt, &e)
}

// ---- verification of what a device sends ----

// VerifyCard checks a device card's self-signature and that the id matches its approve key.
func VerifyCard(e Envelope) (DeviceCard, error) {
	var c DeviceCard
	p, err := UnB64(e.Payload)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(p, &c); err != nil {
		return c, fmt.Errorf("card: %w", err)
	}
	ak, err := UnB64(c.ApproveKey)
	if err != nil {
		return c, err
	}
	if _, err := VerifyES256(e, ak); err != nil {
		return c, fmt.Errorf("card: %w", err)
	}
	if c.V != Version || c.DeviceID != DeviceID(ak) || e.Kid != c.DeviceID {
		return c, errors.New("card: version, device id and approve key do not match")
	}
	for _, k := range []string{c.DenyKey, c.EncKey} {
		raw, err := UnB64(k)
		if err != nil {
			return c, err
		}
		if _, err := ParseP256(raw); err != nil {
			return c, fmt.Errorf("card: %w", err)
		}
	}
	return c, nil
}

// VerifyDecision checks a decision envelope against a pinned device card and the record it answers. It does not
// check nonce reuse or the service's state: that is the adapter's job.
func VerifyDecision(e Envelope, card DeviceCard, adapter string, recordPayload []byte, rec Record, now time.Time) (Decision, error) {
	var d Decision
	if e.Kid != card.DeviceID {
		return d, errors.New("decision signed by a different device than claimed")
	}
	// Approve needs the approve key; deny accepts either. Try the approve key first.
	ak, _ := UnB64(card.ApproveKey)
	dk, _ := UnB64(card.DenyKey)
	p, err := VerifyES256(e, ak)
	byApprove := err == nil
	if err != nil {
		if p, err = VerifyES256(e, dk); err != nil {
			return d, errors.New("decision signature matches neither device key")
		}
	}
	if err := json.Unmarshal(p, &d); err != nil {
		return d, fmt.Errorf("decision: %w", err)
	}
	switch {
	case d.V != Version:
		return d, fmt.Errorf("decision version %d", d.V)
	case d.DeviceID != card.DeviceID:
		return d, errors.New("decision names another device")
	case d.Adapter != adapter:
		return d, fmt.Errorf("decision is for adapter %q", d.Adapter)
	case d.RequestID != rec.ID:
		return d, errors.New("decision is for another request")
	case d.RecordHash != B64(Hash(recordPayload)):
		return d, errors.New("decision signs a different record than the one sent")
	case d.Nonce != rec.Nonce:
		return d, errors.New("decision nonce does not match the record")
	case d.Decision != Approve && d.Decision != Deny:
		return d, fmt.Errorf("unknown decision %q", d.Decision)
	case d.Decision == Approve && !byApprove:
		return d, errors.New("approve not signed with the approve key")
	case now.Sub(time.Unix(d.TS, 0)).Abs() > MaxSkew:
		return d, errors.New("decision timestamp outside the allowed window")
	case now.Unix() > rec.ExpiresAt:
		return d, errors.New("request expired")
	}
	return d, nil
}
