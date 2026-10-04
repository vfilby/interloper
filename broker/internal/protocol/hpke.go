package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// HPKE (RFC 9180), mode base, one suite only: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM. That is
// CryptoKit's HPKE.Ciphersuite.P256_SHA256_AES_GCM_256, which the app opens with its Secure Enclave key. Go 1.25 has
// no crypto/hpke; this is the minimum of it: single-shot seal and open (sequence 0), no PSK, no exporter.

const (
	kemID   = 0x0010
	kdfID   = 0x0001
	aeadID  = 0x0002
	nSecret = 32
	nK      = 32
	nN      = 12
)

// SuiteHPKE names the suite in a sealed box.
const SuiteHPKE = "hpke-p256-sha256-aes256gcm"

// HPKEInfo is the info string bound into every sealed record.
var HPKEInfo = []byte("wga/v1/record")

var (
	kemSuite  = cat([]byte("KEM"), i2osp(kemID, 2))
	hpkeSuite = cat([]byte("HPKE"), i2osp(kemID, 2), i2osp(kdfID, 2), i2osp(aeadID, 2))
)

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func i2osp(n, w int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(n))
	return b[8-w:]
}

func labeledExtract(suite, salt []byte, label string, ikm []byte) ([]byte, error) {
	return hkdf.Extract(sha256.New, cat([]byte("HPKE-v1"), suite, []byte(label), ikm), salt)
}

func labeledExpand(suite, prk []byte, label string, info []byte, l int) ([]byte, error) {
	return hkdf.Expand(sha256.New, prk, string(cat(i2osp(l, 2), []byte("HPKE-v1"), suite, []byte(label), info)), l)
}

func extractAndExpand(dh, kemContext []byte) ([]byte, error) {
	prk, err := labeledExtract(kemSuite, nil, "eae_prk", dh)
	if err != nil {
		return nil, err
	}
	return labeledExpand(kemSuite, prk, "shared_secret", kemContext, nSecret)
}

// aeadFor runs the mode-base key schedule and returns the AEAD with its base nonce.
func aeadFor(shared, info []byte) (cipher.AEAD, []byte, error) {
	pskIDHash, err := labeledExtract(hpkeSuite, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, nil, err
	}
	infoHash, err := labeledExtract(hpkeSuite, nil, "info_hash", info)
	if err != nil {
		return nil, nil, err
	}
	ctx := cat([]byte{0x00}, pskIDHash, infoHash)
	secret, err := labeledExtract(hpkeSuite, shared, "secret", nil)
	if err != nil {
		return nil, nil, err
	}
	key, err := labeledExpand(hpkeSuite, secret, "key", ctx, nK)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := labeledExpand(hpkeSuite, secret, "base_nonce", ctx, nN)
	if err != nil {
		return nil, nil, err
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	a, err := cipher.NewGCM(b)
	return a, nonce, err
}

// hpkeSeal encrypts pt to pkR; enc is the 65-byte encapsulated ephemeral key. rnd nil means crypto/rand.
func hpkeSeal(rnd io.Reader, pkR *ecdh.PublicKey, info, aad, pt []byte) (enc, ct []byte, err error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	skE, err := ecdh.P256().GenerateKey(rnd)
	if err != nil {
		return nil, nil, err
	}
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, err
	}
	enc = skE.PublicKey().Bytes()
	shared, err := extractAndExpand(dh, cat(enc, pkR.Bytes()))
	if err != nil {
		return nil, nil, err
	}
	a, nonce, err := aeadFor(shared, info)
	if err != nil {
		return nil, nil, err
	}
	return enc, a.Seal(nil, nonce, pt, aad), nil
}

// hpkeOpen is the receiving side. The app does this in Swift; Go has it for tests and the software test device.
func hpkeOpen(skR *ecdh.PrivateKey, enc, info, aad, ct []byte) ([]byte, error) {
	pkE, err := ecdh.P256().NewPublicKey(enc)
	if err != nil {
		return nil, errors.New("hpke: bad encapsulated key")
	}
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, err
	}
	shared, err := extractAndExpand(dh, cat(enc, skR.PublicKey().Bytes()))
	if err != nil {
		return nil, err
	}
	a, nonce, err := aeadFor(shared, info)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, ct, aad)
}
