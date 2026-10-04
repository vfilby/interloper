// Package softdevice is a device with software keys: the phone's half of the protocol, for tests and for the
// `wga-device` command line stand-in. It is never a real approver: its keys are files, not Secure Enclave keys.
package softdevice

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"warpgate-approver/broker/internal/protocol"
)

type Device struct {
	Name    string
	Approve *ecdsa.PrivateKey
	Deny    *ecdsa.PrivateKey
	Enc     *ecdh.PrivateKey
}

func New(name string) (*Device, error) {
	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	d, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	e, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Device{Name: name, Approve: a, Deny: d, Enc: e}, nil
}

func pub(k *ecdsa.PrivateKey) []byte {
	b, _ := k.PublicKey.Bytes() // X9.63 uncompressed
	return b
}

func (d *Device) ID() string { return protocol.DeviceID(pub(d.Approve)) }

// Card returns the signed device card.
func (d *Device) Card(now time.Time) (protocol.Envelope, error) {
	return protocol.SignES256(d.Approve, d.ID(), protocol.DeviceCard{
		V: protocol.Version, DeviceID: d.ID(), Name: d.Name,
		ApproveKey: protocol.B64(pub(d.Approve)), DenyKey: protocol.B64(pub(d.Deny)),
		EncKey: protocol.B64(d.Enc.PublicKey().Bytes()), CreatedAt: now.Unix(),
	})
}

// Opened is a record the device decrypted and verified.
type Opened struct {
	Record  protocol.Record
	Payload []byte
}

// Read opens a box and verifies the adapter's signature with the pinned adapter key.
func (d *Device) Read(box protocol.Sealed, adapterKey []byte) (Opened, error) {
	env, err := protocol.Open(d.Enc, box)
	if err != nil {
		return Opened{}, err
	}
	p, err := protocol.VerifyEd25519(env, adapterKey)
	if err != nil {
		return Opened{}, fmt.Errorf("record from %s: %w", env.Kid, err)
	}
	var r protocol.Record
	if err := json.Unmarshal(p, &r); err != nil {
		return Opened{}, err
	}
	if r.Adapter != env.Kid {
		return Opened{}, errors.New("record names another adapter than its signer")
	}
	return Opened{Record: r, Payload: p}, nil
}

// Decide signs a decision on an opened record: approve with the approve key, deny with the deny key.
func (d *Device) Decide(o Opened, decision string, now time.Time) (protocol.Envelope, error) {
	k := d.Deny
	if decision == protocol.Approve {
		k = d.Approve
	}
	return protocol.SignES256(k, d.ID(), protocol.Decision{
		V: protocol.Version, RequestID: o.Record.ID, Adapter: o.Record.Adapter, Decision: decision,
		RecordHash: protocol.B64(protocol.Hash(o.Payload)), Nonce: o.Record.Nonce, DeviceID: d.ID(), TS: now.Unix(),
	})
}

// file is the on-disk form, for the command line stand-in. Private keys in a file: test use only.
type file struct {
	Name    string `json:"name"`
	Approve []byte `json:"approve"`
	Deny    []byte `json:"deny"`
	Enc     []byte `json:"enc"`
}

func (d *Device) Save(path string) error {
	ab, err := d.Approve.Bytes()
	if err != nil {
		return err
	}
	db, err := d.Deny.Bytes()
	if err != nil {
		return err
	}
	b, err := json.Marshal(file{Name: d.Name, Approve: ab, Deny: db, Enc: d.Enc.Bytes()})
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func Load(path string) (*Device, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	a, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), f.Approve)
	if err != nil {
		return nil, err
	}
	dn, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), f.Deny)
	if err != nil {
		return nil, err
	}
	e, err := ecdh.P256().NewPrivateKey(f.Enc)
	if err != nil {
		return nil, err
	}
	return &Device{Name: f.Name, Approve: a, Deny: dn, Enc: e}, nil
}
