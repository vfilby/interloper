# warpgate-approver: design

Approve or deny Warpgate ticket requests from an iPhone, securely, on or off the home network.

> "Claude needs RW access to forge-01 to accomplish task X" → Face ID → Approve.

Status: design (2026-09-30). Warpgate side ready to apply (`fnet-infrastructure` 571ba88); nothing else built.

## Decisions

| # | Decision | Date |
|---|---|---|
| D1 | iOS only (native Swift). The paid Apple Developer account is available (APNs, App Attest, installs that last longer than 7 days). | 2026-09-30 |
| D2 | VPN exists but is not always on. Off-network approvals must not depend on it. When it is on (or on LAN), the app talks to the broker directly. | 2026-09-30 |
| D3 | Own project (this folder). The Warpgate side (approver user and admin role) lives in `fnet-infrastructure/bastion` (`hosts.toml` `[approvers.approver]`, `wg-apply`). | 2026-09-30 |
| D4 | Off-network transport is a managed message service, not a VPS: **AWS IoT Core (MQTT)**, deployed with **CDK** into an AWS account the person provides. (Replaces the earlier NATS-on-VPS idea.) | 2026-09-30 |
| D5 | Enrollment and management happen in a separate lightweight web app that is only reachable on LAN/VPN. | 2026-09-30 |
| D6 | Pushover is the stopgap notification channel for phase 1 only; replaced by APNs from the broker. | 2026-09-30 |
| D7 | Broker language: Go (memory-safe, GC'd, single static binary). Memory is bounded by `GOMEMLIMIT` + a container memory limit and by keeping state in SQLite, not in-process maps. Rewritable later. | 2026-09-30 |

## Facts this design rests on

- `cssh` / `cssh-ticket` (fnet-infrastructure/bastion/mac) file requests with `POST /@warpgate/api/ticket-requests`
  using Claude's **non-admin** token, then poll and `activate`. Today's only notification is `terminal-notifier` on the Mac.
- Deployed Warpgate is v0.28.6. Relevant admin API:
  - `GET /@warpgate/admin/api/ticket-requests?status=Pending`;
  - `POST .../ticket-requests/:id/approve` (no body);
  - `POST .../ticket-requests/:id/deny` (`{reason}`);
  - admin roles (`/admin-roles`, `/users/{id}/admin-roles/{role_id}`).

  Approve and deny are gated on admin permission `ticket_requests_manage`.
- `TicketRequest` = `{id, user_id, target_id, requested_duration_seconds, description, status, created, resolved_by_user_id, ticket_id, resolved_at, deny_reason}`.
- Warpgate has **no webhooks**: new requests are found by polling.
- Approve takes **no body**: you approve exactly the duration requested. Caps are enforced by denying.
- Warpgate cannot restrict which targets a user may *request*; the approver is the gate.
- Warpgate's `allowed_ip_ranges` is checked for interactive and ticket logins, not for API tokens, so the approver
  token cannot be IP-pinned. Its protection is where it lives (interloper only).

## Core principle

The phone never holds a Warpgate credential. It holds a non-exportable Secure Enclave key whose use needs Face ID or
the app PIN. The **broker**, next to Warpgate, holds the scoped approver token. It calls `approve` only for a valid
device signature over the exact record the user was shown. Every transport in between (APNs, Pushover, AWS IoT Core,
the internet) is untrusted and can at most drop or delay messages. Everything fails closed.

## Architecture

```
 cssh (Claude) / maggy ──POST ticket-request──▶ Warpgate (interloper, LAN only)
                                                    ▲ poll Pending, approve/deny
                                                    │ token: user `approver`, admin role `ticket-approver`
                                                    │        = ticket_requests_manage only
                                  ┌──────── approval-broker (interloper, docker) ────────┐
                                  │   admin web UI (LAN/VPN, behind Warpgate HTTP target) │
                                  └──┬──────────────┬──────────────────────▲─────────────┘
                     outbound only   │ APNs push    │ MQTT/TLS (mTLS, 8883 or 443+ALPN)
                                     ▼              ▼                      │
                                 iPhone ◀──── AWS IoT Core (managed MQTT) ─┘
                                   │  on LAN/VPN: direct HTTPS to broker (IoT Core skipped)
```

### 1. approval-broker (interloper)

- Runs on interloper beside Warpgate, **never** on a host where Claude or an agent has a tier (home, n, drones, …):
  whoever can read its Warpgate token can approve.
- Warpgate side (done in `fnet-infrastructure`, applied by the person with `wg-apply`):
  - user `approver`: API token only (no password/OTP/SSO/keys), no access roles, SSH public-key-only with no keys;
  - admin role `ticket-approver`, which holds exactly `ticket_requests_manage`;
  - token: `wg-apply --mint-token approver | ssh interloper 'sudo sh -c "umask 077; cat > /opt/warpgate-approver/secrets/warpgate-token"'`.
- Loop: poll Pending every ~5 s → for each new request build the canonical **request record**:
  `{v, request_id, requester, target, tier, duration_s, description, created_at, broker_nonce, expires_at}`
  → sign (broker Ed25519 key) → encrypt to each enrolled device → deliver (APNs + IoT Core).
- **Policy, applied before anything reaches the phone:**
  - requester allowlist (`claude`, `maggy`);
  - target must be a known `*-rw` / `*-admin`;
  - duration caps (e.g. rw ≤ 2 h, admin ≤ 30 min), over-cap requests are auto-denied with a reason;
  - requests expire after 15 min;
  - burst rate limit (approval fatigue).
- Decision verification, all must hold:
  - signature by an enrolled, non-revoked device key;
  - `broker_nonce` unused;
  - timestamp within 5 min;
  - `record_hash` matches what the broker sent;
  - request **still Pending** in Warpgate with the same target/requester/duration.

  Then approve/deny.
- State (devices, nonces, sent records, audit log) in SQLite on a volume; the audit log is append-only.
- Go; `GOMEMLIMIT` ≈ 64 MiB, container limit 128 MiB, no unbounded in-memory caches.

### 2. iOS app

- **Approval key**: Secure Enclave P-256, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, access control
  `.privateKeyUsage` + `[.biometryCurrentSet, .or, .applicationPassword]`.
  - `biometryCurrentSet`: newly enrolled faces or fingers invalidate the key, so a thief who knows the passcode can't add their own face.
  - `applicationPassword`: the "PIN" is the app's own PIN, enforced by the Secure Enclave, **not** the device passcode.
- **Deny key**: second SE key, device-unlocked only (no biometry). Deny is safe-direction but still signed.
- **Decrypt key**: SE P-256 key-agreement key, no biometry, `AfterFirstUnlockThisDeviceOnly`, used by the Notification
  Service Extension to decrypt pushes.
- **Transport key**: key for the AWS IoT client certificate (mTLS). Preferably a fourth SE key (non-exportable); whether
  an SE-backed `SecIdentity` works with the chosen MQTT client is a phase-3/4 spike. The fallback is a Keychain
  `ThisDeviceOnly` software key. Either is fine: the transport credential is anti-abuse, not the security boundary.
- **Notification Service Extension**: decrypts, verifies the broker signature, and drops anything unverifiable. Display
  order puts the authoritative fields first: **requester, host, tier (RW amber / ADMIN red), duration**; then the
  requester's reason, quoted, labelled as the requester's claim.
- **Approve**: opens the app (foreground action) → Face ID/PIN → signs
  `{v, request_id, decision, record_hash = sha256(record), broker_nonce, device_id, ts}`.
  Admin tier needs a second deliberate gesture (slide to approve).
- **Deny**: lock-screen action (`.authenticationRequired`), signed with the deny key.
- **Transport choice at send time**: broker reachable directly (LAN/VPN) → HTTPS to broker; otherwise → MQTT publish
  to IoT Core. The app shows which path was used and the broker's confirmation.
- **On open**: fetch pending records (direct, or retained messages on IoT Core), so a dropped push loses nothing.
- **Long-lived**: no sessions or tokens expire; enrollment lasts until revoked. The IoT device certificate is issued for
  a long validity. Distribution: ad-hoc/development profile (1 year) or TestFlight (90-day builds).

### 3. Off-network transport: AWS IoT Core (CDK)

Why IoT Core rather than the alternatives:

| Option | Verdict |
|---|---|
| **AWS IoT Core (MQTT)** | **Chosen.** Per-device X.509 identity; per-device topic ACLs via policy variables; persistent sessions and retained messages (nothing lost while the phone or broker is offline); serverless; costs cents per month. |
| SQS / SNS | The phone would need AWS IAM credentials (Cognito or per-device IAM users) and per-device queues; no subscribe model. |
| Amazon MQ | An always-on broker instance you pay for and patch: a VPS in all but name. |
| Synadia Cloud (managed NATS), HiveMQ Cloud | Would work; another vendor for no gain over IoT Core. |

Design:
- One AWS account (preferably dedicated, or at least this stack alone in it), region us-west-2 unless you prefer another.
- **Identities**: every client is an IoT *thing* with its own certificate.
  - `wga-broker`: key generated on interloper; the certificate is issued from its CSR at setup.
  - Each iPhone `wga-dev-<id>`: its certificate is created **from a CSR made on the phone**
    (`CreateCertificateFromCsr`), so the private key never leaves the device.
- **Topics and policies** (all policies require `iot:Connection.Thing.IsAttached`, and the client id must equal the
  thing name):

  | client | publish | subscribe / receive |
  |---|---|---|
  | `wga-broker` | `wga/req/*/*`, `wga/ack/*` | `wga/dec/*` |
  | device `${iot:Connection.Thing.ThingName}` | `wga/dec/${ThingName}` | `wga/req/${ThingName}/*`, `wga/ack/${ThingName}` |

  - `wga/req/<device>/<request_id>`: encrypted, broker-signed record, **retained**. The broker publishes an empty
    retained message when the request resolves or expires.
  - `wga/dec/<device>`: signed decision, QoS 1. The broker keeps a persistent session, so decisions queue while it is offline.
  - `wga/ack/<device>`: broker confirmation (approved / denied / rejected + why).
- **Enrollment and revocation** are AWS control-plane calls made by the broker:
  - enrollment: `CreateCertificateFromCsr`, `CreateThing`, `AttachThingPrincipal`, `AttachPolicy`;
  - revocation: `UpdateCertificate REVOKED`, then delete.

  The broker's AWS credentials come from **IAM Roles Anywhere** (a small private CA kept offline by the person; no
  static keys). The fallback is an IAM user with a key scoped to exactly those actions on `wga-*` resources.
  Compromise of these credentials only lets someone mint transport identities, which still can't sign decisions.
- Observability: IoT Core logs (WARN) to CloudWatch, CloudTrail for control-plane calls, and a CloudWatch alarm on
  broker disconnects.
- **CDK app** (TypeScript, `infra/`):
  - resources: thing type, the two IoT policies, the logging role and log level, the Roles Anywhere trust
    anchor/profile/role (or the scoped IAM user), alarms;
  - outputs: the ATS data endpoint and the role ARNs;
  - things and certificates are **not** in CDK: they are made at runtime by enrollment.
- If AWS is unreachable, off-network approval stops. LAN/VPN approval and the Warpgate web UI still work.

### 4. Management app (LAN/VPN only)

- Served by the broker on a separate listener bound to interloper's LAN address. Published as a **Warpgate HTTP
  target** that only your admin role can reach, so Warpgate's password+OTP login gates it and requests are recorded.
  interloper is not reachable from the internet, so LAN/VPN-only needs no extra enforcement.
- Server-rendered HTML (Go templates + htmx), no SPA and no JS build chain.
- Screens:
  - **Devices**: enroll, list (last seen, last approval), revoke, rotate.
  - **Pending**: current requests, with approve/deny as a fallback.
  - **Audit**: searchable decision log.
  - **Policy**: requester allowlist, duration caps, expiry, rate limits.
  - **Health**: Warpgate poll, IoT connection, APNs/Pushover, expiry of the Warpgate token and certificates.
- **Enrollment** (phone must be on LAN/VPN; never via IoT Core):
  1. Admin clicks *Enroll device*: the UI shows a QR code with `{broker_url, broker_pubkey, one-time code (5 min)}`.
  2. The app scans it and creates its SE keys. It POSTs the public keys, an IoT CSR and an **App Attest** assertion
     bound to the code directly to the broker.
  3. Both screens show a short fingerprint of the device key; the admin confirms in the web UI.
  4. The broker records the device, has AWS issue the IoT certificate from the CSR, and returns the certificate and
     the IoT endpoint.
- Claude has no login on interloper and no admin role in Warpgate, so it cannot reach enrollment.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Agent approves its own request | Agent tokens have no admin rights; approver token is only on interloper; approval needs an SE signature |
| Misleading reason ("read logs" on forge-01-admin) | Authoritative fields (host, tier, requester, duration) shown first; reason labelled as the requester's claim |
| Stolen unlocked phone | SE key requires Face ID or app PIN, enforced by the Secure Enclave rather than app code |
| Thief knows the device passcode | `biometryCurrentSet` + separate app PIN |
| APNs / Pushover / AWS IoT Core compromised | Pushes broker-signed and encrypted, decisions device-signed, nonce + timestamp prevent replay; worst case is DoS (fail closed) |
| Broker's AWS credentials stolen | Can mint IoT transport identities only; they can't sign decisions |
| Request swapped under an approval | Decision signs `record_hash`; broker re-checks Warpgate state before approving |
| Approval fatigue (spam requests) | Rate limit, bursts collapsed, admin tier needs a second gesture |
| Over-long ticket | Duration caps enforced by auto-deny (approve can't shorten) |
| Broker compromised | Same host and trust as Warpgate; its Warpgate token can only approve/deny tickets |
| Lost phone | Revoke in management app (SE keys and IoT certificate); Warpgate web UI remains the fallback |

## Build phases

1. **Broker v0 + Pushover (stopgap).**
   - Apply the `approver` user and role (`wg-apply`), mint its token to interloper.
   - Broker polls, applies policy and auto-denies, writes the audit log.
   - Pushover notification linking to `https://interloper.home.example/@warpgate/admin#/config/tickets`.
   - Approval still happens in the Warpgate UI (LAN/VPN).
   - Pushover sees host names and reasons in plain text; acceptable for a trial only.
2. **Management UI v0**: Warpgate HTTP target; pending, audit, policy, health. Devices screen stubbed.
3. **iOS app v0, direct path only**: enrollment, pending list, signed approve/deny over LAN/VPN. Includes the spike on
   an SE-backed identity for MQTT mTLS.
4. **Off-network**: CDK stack (IoT Core, Roles Anywhere), broker MQTT client, IoT certificate at enrollment, APNs from the
   broker, Notification Service Extension; retire Pushover.
5. **Hardening**: rate limits, admin second gesture, key/cert/token rotation, optional Apple Watch approve.

## Open questions

- AWS account for phase 4: account id, region (default us-west-2), and how deploys authenticate from the Mac. Preferred:
  a deploy role Claude assumes via a named AWS CLI profile; `cdk bootstrap` once.
- Roles Anywhere private CA: where the offline root lives (YubiKey PIV slot? 1Password?).
- Which VPN (UniFi WireGuard?). Only matters for testing the direct path from outside.

## Planned layout

```
broker/     Go service: Warpgate poller, policy, signer, APNs/Pushover/MQTT, management UI
ios/        Xcode project: app + Notification Service Extension
infra/      CDK app (TypeScript): IoT Core policies, logging, Roles Anywhere, alarms
deploy/     compose for interloper
docs/       this file, protocol spec (record/decision formats), runbooks
```
