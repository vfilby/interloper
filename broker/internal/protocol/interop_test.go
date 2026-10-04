package protocol_test

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"warpgate-approver/broker/internal/protocol"
	"warpgate-approver/broker/internal/softdevice"
)

// Interop with the Swift side (CryptoKit), through files in testdata/interop at the repository root:
//
//	go-sealed.json      written here with WGA_WRITE_FIXTURE=1: a device's raw private keys, an adapter key and a
//	                    sealed record. The app's tests open it with CryptoKit HPKE and verify the adapter signature.
//	swift-decision.json written by the Swift side: a card and a decision on that record, signed by CryptoKit.
//	                    TestSwiftDecision verifies it here.
//
// The private keys in go-sealed.json are test keys and nothing else.

var interopDir = filepath.Join("..", "..", "..", "testdata", "interop")

type goSealed struct {
	DeviceApproveRaw string            `json:"device_approve_raw"` // 32-byte P-256 scalars (CryptoKit rawRepresentation)
	DeviceDenyRaw    string            `json:"device_deny_raw"`
	DeviceEncRaw     string            `json:"device_enc_raw"`
	Card             protocol.Envelope `json:"card"`
	AdapterID        string            `json:"adapter_id"`
	AdapterKey       string            `json:"adapter_key"`
	Box              protocol.Sealed   `json:"box"`
	RecordPayload    string            `json:"record_payload"` // what the decision's record_hash must cover
	Now              int64             `json:"now"`
}

type swiftDecision struct {
	Card     protocol.Envelope `json:"card"`
	Decision protocol.Envelope `json:"decision"`
}

func TestWriteGoSealed(t *testing.T) {
	if os.Getenv("WGA_WRITE_FIXTURE") == "" {
		t.Skip("set WGA_WRITE_FIXTURE=1 to rewrite testdata/interop/go-sealed.json")
	}
	now := time.Now()
	dev, _ := softdevice.New("interop device")
	ce, _ := dev.Card(now)
	adPub, adKey, _ := ed25519.GenerateKey(nil)
	rec := protocol.Record{V: 1, ID: "interop-1", Adapter: "demo", Kind: "demo.test", Shape: protocol.ShapeLease,
		Risk: protocol.RiskHigh, Title: "claude wants ADMIN on build-01", Requester: "claude",
		OnBehalfOf: &protocol.Principal{Principal: "slack:U0123", Display: "Kim", AttestedBy: "agent@agent-host"},
		Facts:      []protocol.Fact{{Label: "Host", Value: "build-01"}, {Label: "Tier", Value: "ADMIN", Level: "danger"}},
		Reason:     "rotate the “certs”‮ — with unicode", Lease: &protocol.Lease{DurationS: 7200, Scope: "build-01-admin"},
		CreatedAt: now.Unix(), ExpiresAt: now.Add(10 * 365 * 24 * time.Hour).Unix(), Nonce: protocol.NewNonce()}
	signed, _ := protocol.SignEd25519(adKey, "demo", rec)
	box, err := protocol.Seal(nil, dev.ID(), dev.Enc.PublicKey().Bytes(), signed)
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := dev.Approve.Bytes()
	db, _ := dev.Deny.Bytes()
	out := goSealed{DeviceApproveRaw: protocol.B64(ab), DeviceDenyRaw: protocol.B64(db), DeviceEncRaw: protocol.B64(dev.Enc.Bytes()),
		Card: ce, AdapterID: "demo", AdapterKey: protocol.B64(adPub), Box: box, RecordPayload: signed.Payload, Now: now.Unix()}
	b, _ := json.MarshalIndent(out, "", "  ")
	if err := os.MkdirAll(interopDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(interopDir, "go-sealed.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestGoSealedOpensInGo keeps the committed fixture honest from this side too.
func TestGoSealedOpensInGo(t *testing.T) {
	var g goSealed
	readJSON(t, "go-sealed.json", &g)
	dev := deviceFromFixture(t, g)
	ak, _ := protocol.UnB64(g.AdapterKey)
	o, err := dev.Read(g.Box, ak)
	if err != nil {
		t.Fatal(err)
	}
	if protocol.B64(o.Payload) != g.RecordPayload {
		t.Fatal("payload differs")
	}
}

func TestSwiftDecision(t *testing.T) {
	var g goSealed
	readJSON(t, "go-sealed.json", &g)
	var s swiftDecision
	readJSON(t, "swift-decision.json", &s)
	card, err := protocol.VerifyCard(s.Card)
	if err != nil {
		t.Fatalf("Swift-made card: %v", err)
	}
	payload, _ := protocol.UnB64(g.RecordPayload)
	var rec protocol.Record
	_ = json.Unmarshal(payload, &rec)
	dp, _ := s.Decision.PayloadBytes()
	var d protocol.Decision
	_ = json.Unmarshal(dp, &d)
	// Judge it at the time it was made: the fixture is old by the time this runs.
	got, err := protocol.VerifyDecision(s.Decision, card, g.AdapterID, payload, rec, time.Unix(d.TS, 0))
	if err != nil {
		t.Fatalf("Swift-made decision: %v", err)
	}
	if got.Decision != protocol.Approve {
		t.Fatalf("decision %q", got.Decision)
	}
}

func readJSON(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(interopDir, name))
	if err != nil {
		t.Skipf("%s missing: %v", name, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func deviceFromFixture(t *testing.T, g goSealed) *softdevice.Device {
	t.Helper()
	dir := t.TempDir()
	a, _ := protocol.UnB64(g.DeviceApproveRaw)
	d, _ := protocol.UnB64(g.DeviceDenyRaw)
	e, _ := protocol.UnB64(g.DeviceEncRaw)
	b, _ := json.Marshal(map[string]any{"name": "fixture", "approve": a, "deny": d, "enc": e})
	p := filepath.Join(dir, "dev.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	dev, err := softdevice.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return dev
}
