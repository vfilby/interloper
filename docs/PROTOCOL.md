# Approval protocol v1

The wire formats shared by adapters (Go), the hub (Go) and the iOS app (Swift). Anything not written here is not
part of the protocol. Architecture and reasoning: [DESIGN.md](DESIGN.md), section "Clearing house".

## Roles

| Role | Holds | Trusted for |
|---|---|---|
| **Adapter** (one per service: Warpgate, Mailpit, Paperless, …) | the service credential; an Ed25519 signing key; the pinned device list | building the request record, verifying decisions, acting |
| **Hub** | nothing that can act: bearer tokens for transport, ciphertexts, metadata | relaying and storing. It can drop or delay; it cannot approve, forge, or read a record |
| **Device** (iPhone) | Secure Enclave keys | showing the record, getting Face ID / PIN, signing the decision |

Every security property below holds with a hostile hub and hostile transports.

## Encodings

- **b64**: base64url without padding (RFC 4648 §5), everywhere.
- **Times**: integer Unix seconds (UTC).
- **JSON**: UTF-8. Readers ignore unknown fields. Nothing is canonicalized: signatures cover the exact payload bytes
  carried in the envelope, and hashes are over those same bytes.
- **Fingerprint** of a public key: the first 8 bytes of SHA-256 over the key's raw encoding, as 4 groups of 4 lower-case
  hex digits: `3f2a-91c0-77de-0b14`.

## Keys

| Key | Algorithm | Public encoding | Where |
|---|---|---|---|
| adapter signing | Ed25519 | 32 raw bytes | file on the adapter's host (0400) |
| device approve | ECDSA P-256 / SHA-256 | X9.63 uncompressed, 65 bytes | Secure Enclave, Face ID (current set) or app PIN |
| device deny | ECDSA P-256 / SHA-256 | X9.63 uncompressed, 65 bytes | Secure Enclave, device unlocked |
| device encryption | P-256 key agreement (HPKE) | X9.63 uncompressed, 65 bytes | Secure Enclave, after first unlock |

ECDSA signatures are the 64-byte raw `r || s` form (CryptoKit `rawRepresentation`). Ed25519 signatures are 64 bytes.

**Device id** = the fingerprint of the approve key without dashes (16 hex digits).

## Signed envelope

```json
{"alg": "ed25519" | "es256", "kid": "<signer id>", "payload": "<b64 bytes>", "sig": "<b64>"}
```

`sig` is over the decoded `payload` bytes. `kid` is the adapter id for `ed25519`, the device id for `es256`. A verifier
checks the signature with the key it has **pinned** for `kid` before parsing the payload, and then checks that the
payload names the same signer (`adapter` / `device_id`).

## Sealed box (adapter → device)

```json
{"suite": "hpke-p256-sha256-aes256gcm", "kid": "<device id>", "enc": "<b64 65 bytes>", "ct": "<b64>"}
```

RFC 9180 HPKE, mode base: DHKEM(P-256, HKDF-SHA256) `0x0010`, HKDF-SHA256 `0x0001`, AES-256-GCM `0x0002`
(CryptoKit `HPKE.Ciphersuite.P256_SHA256_AES_GCM_256`). `info` = the ASCII bytes `wga/v1/record`, `aad` = empty,
one message per context. The plaintext is the JSON of a **signed envelope** whose payload is a request record: sign,
then encrypt, so the hub sees neither the record nor the adapter's signature over it.

## Request record (adapter → device)

```json
{
  "v": 1,
  "id": "<adapter-scoped request id>",
  "adapter": "warpgate",
  "kind": "ssh.ticket",
  "shape": "once" | "lease",
  "risk": "normal" | "elevated" | "high",
  "title": "helper wants RW on build-01",
  "requester": "helper",
  "on_behalf_of": {"principal": "slack:U0123", "display": "Kim", "attested_by": "agent@agent-host"},
  "facts": [
    {"label": "Host", "value": "build-01"},
    {"label": "Tier", "value": "RW", "level": "warn"},
    {"label": "Duration", "value": "2h"}
  ],
  "reason": "<requester's own words>",
  "lease": {"duration_s": 7200, "scope": "build-01-rw", "max_uses": 0},
  "created_at": 1790000000,
  "expires_at": 1790000900,
  "nonce": "<b64 16 random bytes>"
}
```

- `title` and `facts` are written by the adapter from the service's own state: they are the **authoritative**
  part and are shown first. `level` is `""`, `"warn"` or `"danger"`. The app renders any kind from these fields
  alone. It needs no kind-specific code.
- `reason` is the requester's claim. The app shows it after the facts, quoted and labelled as the requester's.
- `on_behalf_of` is optional: the human the requester says it acts for, and which component attested it. It is a
  claim by `attested_by`, not by the requester.
- `lease` is present only when `shape` = `lease`. `max_uses` 0 means unlimited within the duration.
- `risk` = `high` makes the app ask for a second deliberate gesture before signing an approval.
- `nonce` makes every record unique. It is echoed in the decision and is single-use at the adapter.

## Decision (device → adapter)

A signed envelope (`es256`, `kid` = device id) over:

```json
{
  "v": 1,
  "request_id": "<record id>",
  "adapter": "warpgate",
  "decision": "approve" | "deny",
  "record_hash": "<b64 SHA-256 of the record payload bytes>",
  "nonce": "<record nonce>",
  "device_id": "<device id>",
  "ts": 1790000123
}
```

- `approve` must be signed with the device's **approve** key. `deny` may be signed with the deny key or the
  approve key.
- The adapter acts only if all of these hold:
  - the device is pinned and not revoked, and the key matches the decision;
  - `adapter` is this adapter;
  - `record_hash` equals the hash of the record it sent;
  - the nonce is unused;
  - `|now - ts|` ≤ 300 s;
  - the record has not expired;
  - the service still shows the request pending and unchanged.

  Otherwise it rejects the decision and does nothing.

## Acknowledgement (adapter → device)

A signed envelope (`ed25519`, `kid` = adapter id) over:

```json
{"v": 1, "request_id": "…", "adapter": "warpgate", "outcome": "approved" | "denied" | "rejected" | "expired" | "failed",
 "detail": "…", "decision_hash": "<b64 SHA-256 of the decision payload bytes, or empty>", "ts": 1790000125}
```

The app shows the outcome only after verifying the adapter's signature. An unverified ack is shown as "unconfirmed".

`approved`, `denied` and `expired` are **final**: the hub stops offering the request. `rejected` (the decision did not
verify) and `failed` (the service call failed) are **notes**: the request stays pending, and the person may decide
again. That produces a fresh decision with a new `ts` and the same record nonce. A record's nonce is used up only when
the adapter acts on it.

## Device card (enrollment)

A signed envelope (`es256`, `kid` = device id, signed with the approve key: enrollment needs Face ID) over:

```json
{"v": 1, "device_id": "…", "name": "Vince's iPhone", "approve_key": "<b64>", "deny_key": "<b64>",
 "enc_key": "<b64>", "created_at": 1790000000}
```

Adapters pin device cards. They do not trust the hub's device list. Adding a device to an adapter is a local admin
step (`adapter trust add card.json`). The admin compares the printed fingerprint with the one on the phone.

## Hub HTTP API (transport only)

Every route requires `Authorization: Bearer <token>`. Adapter tokens and device tokens are different kinds and
reach different routes. Tokens are transport credentials: they stop LAN noise and abuse, not forgery.

| Route | Caller | Purpose |
|---|---|---|
| `POST /v1/adapter/requests` | adapter | `{id, kind, expires_at, boxes: {device_id: sealed}}`: publish a request |
| `GET /v1/adapter/decisions?wait=25` | adapter | long-poll: `[{request_id, device_id, decision: envelope}]` not yet taken |
| `POST /v1/adapter/acks` | adapter | `{request_id, ack: envelope}`: resolves the request at the hub |
| `POST /v1/enroll` | new device (one-time code instead of a token) | `{code, card: envelope}` → `{device_id, token}` |
| `GET /v1/device/adapters` | device | `[{id, key, fingerprint}]`: adapter keys to pin (trust on first use, fingerprints shown) |
| `GET /v1/device/requests` | device | `[{id, adapter, kind, created_at, expires_at, box}]`: pending requests that have a box for this device |
| `POST /v1/device/decisions` | device | `{adapter, request_id, decision: envelope}` |
| `GET /v1/device/acks?since=<unix>` | device | `[{adapter, request_id, ack: envelope}]` |

The enrollment link the management UI shows as a QR code (and as text):

```
wga://enroll?hub=<url-encoded hub base URL>&code=<one-time code>
```

The code expires after 10 minutes and works once.
