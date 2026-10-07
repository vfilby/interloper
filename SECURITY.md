# Security

Interpose decides whether an agent gets access to something (an SSH ticket today). Its security matters more than its
features; reports are welcome.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this repository. Please do not open a public
issue or pull request for a vulnerability. Include what an attacker needs (network position, which component they
control), what they gain, and steps to reproduce.

Only `main` is supported; there are no maintained release branches.

## Security model

The full reasoning is in [docs/DESIGN.md](docs/DESIGN.md) and the wire formats in [docs/PROTOCOL.md](docs/PROTOCOL.md).
In short, every property below is meant to hold with a **hostile hub and hostile transports**.

| Component | Holds | If it is compromised |
|---|---|---|
| **Phone** (iOS app) | Secure Enclave keys (approve, deny) behind Face ID or the app PIN; encryption key | an attacker with the unlocked phone and the user's biometrics/PIN can approve as that user. Remove the device from the account on another phone |
| **Adapter** (one per service, on that service's host) | the service credential (scoped: Warpgate's can only manage ticket requests); its Ed25519 signing key; its trust list of users | the attacker has that service's credential, which owning the host already gave them. Other services are unaffected |
| **Hub** | bearer tokens for transport, ciphertexts, routing metadata, roster chains, the audit of what it relayed | it can drop or delay messages and see metadata (which adapter, kind, timing). It cannot read a request, forge or alter a decision, or add a device to anyone |
| **Network / reverse proxy** | TLS termination | the same as the hub: transport only |

What enforces that:
- **Requests** are signed by the adapter (Ed25519) and sealed separately to each trusted device (HPKE, P-256). The
  phone checks the adapter's signature against the key it pinned (fingerprint shown to compare).
- **Decisions** are signed on the phone (ES256, Secure Enclave). The adapter verifies the device is on the current
  roster of a user it trusts, the key type, its own id, the hash of the exact record it sent, a single-use nonce, a
  300-second time window and the record's expiry, and re-reads the service before acting.
- **Trust is per user and pinned at each adapter** (user id + account fingerprint, set by an operator). Rosters are
  hash chains signed by the user's own devices; adapters verify them and refuse rollbacks and forks. A new phone joins
  only when an existing phone approves it with Face ID.
- **Fail closed**: unanswered requests are denied at the service; decisions that do not verify do nothing; an
  unreadable trust list stops the adapter publishing.
- **Hub management UI**: OIDC sign-in, server-rendered with no JavaScript (CSP `default-src 'none'`), cross-site POSTs
  refused; without OIDC configured it listens on loopback only and answers only to a loopback Host (DNS rebinding).
- **Push notifications** carry fixed text ("Approval request"), never request content.
- **Containers**: distroless, non-root, read-only root filesystem, no capabilities, memory and PID limits. Adapters
  only connect out.

### Known limits

- Off-network transport is not built: phones reach the hub on LAN or VPN.
- Adapter keys and a joining phone's account fingerprint are pinned only once the person confirms them on the phone
  (against what the adapter prints, or what another phone of the account shows); a careless tap still pins.
- Verified so far in tests and the simulator. Not yet verified: Secure Enclave keys on hardware, the Warpgate source
  against a live Warpgate (it is tested through the client's request shapes).
- One device is enough to change a roster (D16 in [docs/DESIGN.md](docs/DESIGN.md)): a phone stolen together with its
  Face ID or app PIN can remove the user's other phones and add its own. Recovery is the hub admin deleting the
  account, then enrolling it again and re-pinning it at each adapter.
- No account recovery key yet: an account whose every phone is lost must be enrolled again and re-trusted at each
  adapter.
- Hub, accepted for now (security audit of 2026-10-04): a device may register any APNs token, so it can have
  another phone woken with the hub's fixed texts; management UI sessions are signed cookies with no server-side
  revocation, so signing out clears only the browser's copy and a stolen cookie works until it expires (12 hours by default);
  the state file is replaced (write, then rename) without fsync, so a power cut can lose the last changes; and the hub
  forgets decisions once an adapter has fetched them, so a lost response loses them. Each of these fails closed: a
  request nobody decides is denied.
- `interpose-device` (the software phone) keeps its keys in a file. It exists for tests; never trust it on a real
  adapter.

## Operating it safely

- **This repository is public.** Real host names, addresses, tokens and keys belong in `.env` files and secret files on
  the hosts, never in commits. Docs use `*.home.example` and `192.0.2.x`.
- Give each adapter its own service account with the narrowest rights the service offers, so it can be revoked alone.
- Read the **account fingerprint off a phone** on the account when running `trust add-user`, never off the hub's page.
- Keep adapter directories (`signing.key`, `hub-token`, trust list) private to the adapter's user; the install script
  sets the permissions.
- Expose the hub only through the reverse proxy; publish its ports on loopback or a private Docker network.

## Development practice

- Every push and pull request runs CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)): vet, tests with the
  race detector (including forged, replayed and stale decisions, rollback and fork attempts), the end-to-end run,
  Go ↔ CryptoKit interop, image builds, and `govulncheck`. `main` only changes through pull requests that pass it.
- Dependencies are few on purpose: the Go side uses the standard library plus an OIDC client and a QR encoder; the app
  has no third-party dependencies.
