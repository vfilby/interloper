# warpgate-approver: design

Approve or deny Warpgate ticket requests from an iPhone, securely, on or off the home network.

> "Claude needs RW access to forge-01 to accomplish task X" → Face ID → Approve.

Status: design (2026-09-30). Nothing built yet.

## Decisions so far

| # | Decision | Date |
|---|---|---|
| D1 | iOS only (native Swift). No Android. | 2026-09-30 |
| D2 | VPN exists but is not always on. Off-network approvals must not depend on it. When it is on (or on LAN), the app talks to the broker directly. | 2026-09-30 |
| D3 | Own project (this folder), not part of `fnet-infrastructure/bastion`. The bastion repo keeps the Warpgate side (role, `approver` user, `hosts.toml`). | 2026-09-30 |
| D4 | Off-network uplink is a message queue (NATS JetStream, self-hosted on a small VPS), not an ad-hoc relay. | 2026-09-30 |
| D5 | Enrollment and management happen in a separate lightweight web app that is only reachable on LAN/VPN. | 2026-09-30 |
| D6 | Pushover is the stopgap notification channel for phase 1 only; replaced by APNs from the broker. | 2026-09-30 |

## Facts this design rests on

- `cssh` / `cssh-ticket` (fnet-infrastructure/bastion/mac) file requests with `POST /@warpgate/api/ticket-requests`
  using Claude's **non-admin** token, then poll and `activate`. Today's only notification is `terminal-notifier` on the Mac.
- Upstream Warpgate: `POST /@warpgate/admin/api/ticket-requests/:id/approve` and `.../deny` (`{reason}`), both gated on
  admin permission `ticket_requests_manage` (migration m00044). Custom admin roles exist (m00032), so a credential that can
  **only** approve/deny tickets is possible without patching Warpgate.
- Warpgate has **no webhooks**: new requests must be found by polling `GET /admin/api/ticket-requests?status=Pending`.
- Approve takes **no body**: you approve exactly the duration requested. Duration caps must be enforced by denying.
- Warpgate cannot restrict which targets a user may *request*; the approver is the gate.

## Core principle

The phone never holds a Warpgate credential. It holds a non-exportable Secure Enclave key whose use needs Face ID or
the app PIN. The **broker**, next to Warpgate, holds the scoped approver token. It calls `approve` only for a valid
device signature over the exact record the user was shown. Every transport in between (APNs, Pushover, NATS, the
internet) is untrusted and can at most drop or delay messages. Everything fails closed.

## Architecture

```
 cssh (Claude) / maggy ──POST ticket-request──▶ Warpgate (interloper, LAN only)
                                                    ▲ poll Pending, approve/deny
                                                    │ token: user `approver`, role = ticket_requests_manage only
                                  ┌──────── approval-broker (interloper, docker) ────────┐
                                  │   admin web UI (LAN/VPN, behind Warpgate HTTP target) │
                                  └──┬──────────────┬──────────────────────▲─────────────┘
                     outbound only   │ APNs push    │ publish requests     │ consume decisions
                                     ▼              ▼                      │
                                 iPhone ◀──── NATS JetStream (VPS, TLS) ───┘
                                   │  on LAN/VPN: direct HTTPS to broker (queue skipped)
```

### 1. approval-broker (interloper)

- Runs on interloper beside Warpgate (`/opt/warpgate/…` or its own compose), **never** on a host where Claude or an
  agent has a tier (home, n, drones, …): whoever can read its token can approve.
- Warpgate side: user `approver`, API-token only (no password/OTP/SSO), admin role `ticket-approver` with only
  `ticket_requests_manage`. Token expiry 1 year, root-only on disk. Managed from `hosts.toml`/`wg-apply` if practical.
- Loop: poll Pending every ~5 s → for each new request build the canonical **request record**:
  `{v, request_id, requester, target, tier, duration_s, description, created_at, broker_nonce, expires_at}`
  → sign (broker Ed25519 key) → encrypt to each enrolled device → deliver (APNs + NATS `REQUESTS` stream).
- **Policy, applied before anything reaches the phone:**
  - requester allowlist (`claude`, `maggy`);
  - target must be a known `*-rw` / `*-admin`;
  - duration caps (e.g. rw ≤ 2 h, admin ≤ 30 min), over-cap requests are auto-denied with a reason;
  - requests expire after 15 min;
  - burst rate limit (N requests / M min makes further requests non-approvable from the phone; approval fatigue).
- Decision verification, all must hold:
  - signature by an enrolled, non-revoked device key;
  - `broker_nonce` unused (single use);
  - decision timestamp within 5 min;
  - `record_hash` matches what the broker sent;
  - the request is **still Pending** in Warpgate with the same target/requester/duration.

  Then call `approve` or `deny`.
- Append-only audit log: every record sent, every decision received (with signature), and every Warpgate call and
  result. Warpgate shows `approver` as approver; the broker log says which device did it.
- Language: Go (first-class NATS client, APNs libraries, single static binary, small image). Assumption, revisit if needed.

### 2. iOS app

- **Approval key**: Secure Enclave P-256, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, access control
  `.privateKeyUsage` + `[.biometryCurrentSet, .or, .applicationPassword]`.
  - `biometryCurrentSet`: newly enrolled faces or fingers invalidate the key, so a thief who knows the passcode can't add their own face.
  - `applicationPassword`: the "PIN" is the app's own PIN, enforced by the Secure Enclave, **not** the device passcode.
- **Deny key**: second SE key, device-unlocked only (no biometry). Deny is safe-direction but still signed.
- **Decrypt key**: SE P-256 key-agreement key, no biometry, `AfterFirstUnlockThisDeviceOnly`, used by the Notification
  Service Extension to decrypt pushes.
- **Notification Service Extension**: decrypts, verifies the broker signature, and drops anything unverifiable. Display
  order puts the authoritative fields first: **requester, host, tier (RW amber / ADMIN red), duration**; then the
  requester's reason, quoted, labelled as the requester's claim.
- **Approve**: opens the app (foreground action) → Face ID/PIN → signs
  `{v, request_id, decision, record_hash = sha256(record), broker_nonce, device_id, ts}`.
  Admin tier needs a second deliberate gesture (slide to approve).
- **Deny**: lock-screen action (`.authenticationRequired`), signed with the deny key.
- **Transport choice at send time**: broker reachable directly (LAN/VPN) → HTTPS to broker; otherwise → publish to
  NATS. The app shows which path was used and the broker's confirmation.
- **On open**: fetch pending records (direct or from the NATS `REQUESTS` stream), so a dropped push loses nothing.
- **Long-lived**: no sessions or tokens expire; enrollment lasts until revoked.
  Requires a paid Apple Developer account: free provisioning expires in 7 days, and APNs and App Attest need the paid
  account. Distribution: ad-hoc/development profile (1 year) or TestFlight (90-day builds).

### 3. Message queue: NATS JetStream on a VPS

Why a queue: acknowledgements, redelivery, TTL, dedupe, per-client auth and subject ACLs, all self-hosted and
observable. It is a **second layer**; the end-to-end signatures remain the security boundary.

- Why a VPS: must be reachable off-VPN without an inbound port into the house. The broker connects **outbound**.
- TLS (Let's Encrypt), plus NATS WebSocket on 443 if carrier networks block 4222.
- Decentralized JWT auth: an operator key (offline, kept by you) signs an account; the **broker holds the account signing
  key** and mints a user JWT per device at enrollment; revocation goes through the account's revocation list. No VPS
  config edits per device.
- Subject permissions:

  | client | publish | subscribe |
  |---|---|---|
  | broker | `wg.req.>` | `wg.dec.>` |
  | device `<id>` | `wg.dec.<id>` | `wg.req.<id>`, own `_INBOX.>` |

- Streams:
  - `REQUESTS`: `wg.req.*`, encrypted records per device, `max_age` 15 min, last-per-subject.
  - `DECISIONS`: `wg.dec.*`, work-queue retention, `max_age` 15 min, dedupe window 15 min with
    `Nats-Msg-Id = broker_nonce`; the broker consumes with a durable consumer and explicit ack.
- The phone connects only while the app is in the foreground (iOS won't keep a socket in the background); APNs wakes it.
- If the VPS is lost, off-network approval stops, and LAN/VPN approval and the Warpgate web UI still work.

### 4. Management app (LAN/VPN only)

- Served by the broker on a separate listener bound to interloper's LAN address. Published as a **Warpgate HTTP
  target** that only your admin role can reach, so Warpgate's password+OTP login gates it and requests are recorded.
  interloper is not reachable from the internet, so LAN/VPN-only needs no extra enforcement.
- Server-rendered HTML (Go templates + htmx), no SPA and no JS build chain.
- Screens:
  - **Devices**: enroll, list (last seen, last approval), revoke, rotate.
  - **Pending**: current requests, with approve/deny as a fallback to the Warpgate UI.
  - **Audit**: searchable decision log.
  - **Policy**: requester allowlist, duration caps, expiry, rate limits.
  - **Health**: Warpgate poll, NATS connection, APNs/Pushover, token expiry dates.
- **Enrollment** (phone must be on LAN/VPN; never via the queue):
  1. Admin clicks *Enroll device*: the UI shows a QR code with `{broker_url, broker_pubkey, one-time code (5 min)}`.
  2. The app scans it and creates its three SE keys. It POSTs the public keys plus an **App Attest** assertion
     bound to the code directly to the broker.
  3. Both screens show a short fingerprint of the device key; the admin confirms in the web UI.
  4. The broker records the device and mints its NATS user JWT. The app stores it in the Keychain (`ThisDeviceOnly`).
     That credential is only anti-spam: it can publish decisions, and those still need SE signatures.
- Claude has no login on interloper and no admin role in Warpgate, so it cannot reach enrollment.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Agent approves its own request | Agent tokens have no admin rights; approver token is only on interloper; approval needs an SE signature |
| Misleading reason ("read logs" on forge-01-admin) | Authoritative fields (host, tier, requester, duration) shown first; reason labelled as the requester's claim |
| Stolen unlocked phone | SE key requires Face ID or app PIN, enforced by the Secure Enclave rather than app code |
| Thief knows the device passcode | `biometryCurrentSet` + separate app PIN |
| APNs / Pushover / NATS / VPS compromised | Pushes broker-signed and encrypted, decisions device-signed, nonce + timestamp prevent replay; worst case is DoS (fail closed) |
| Request swapped under an approval | Decision signs `record_hash`; broker re-checks Warpgate state before approving |
| Approval fatigue (spam requests) | Rate limit, bursts collapsed, admin tier needs a second gesture |
| Over-long ticket | Duration caps enforced by auto-deny (approve can't shorten) |
| Broker compromised | Same host and trust as Warpgate; token can only approve/deny tickets |
| Lost phone | Revoke in management app; Warpgate web UI remains the fallback |

## Build phases

1. **Broker v0 + Pushover (stopgap).**
   - Warpgate `approver` user and role; broker polls, applies policy and auto-denies, writes the audit log.
   - Pushover notification linking to `https://interloper.home.example/@warpgate/admin#/config/tickets`.
   - Approval still happens in the Warpgate UI (LAN/VPN).
   - Note: Pushover sees host names and reasons in plain text; acceptable for a trial only.
2. **Management UI v0**: Warpgate HTTP target; pending, audit, policy, health. Devices screen stubbed.
3. **iOS app v0, direct path only**: enrollment, pending list, signed approve/deny over LAN/VPN. Proves the crypto
   and the UX with no queue involved.
4. **Off-network**: NATS JetStream on a VPS + APNs from the broker; Notification Service Extension; retire Pushover.
5. **Hardening**: rate limits, admin second gesture, key/token rotation, optional Apple Watch approve.

## Open questions

- Apple Developer Program membership: needed from phase 3 (App Attest; installs lasting more than 7 days) and phase 4 (APNs).
- VPS provider/location for NATS (phase 4).
- Which VPN (UniFi WireGuard?). Only matters for testing the direct path from outside.
- Whether `approver` user/role creation belongs in `hosts.toml` + `wg-apply`, or is made by hand once.

## Planned layout

```
broker/     Go service: Warpgate poller, policy, signer, APNs/Pushover/NATS, management UI
ios/        Xcode project: app + Notification Service Extension
deploy/     compose for interloper, NATS config for the VPS
docs/       this file, protocol spec (record/decision formats), runbooks
```
