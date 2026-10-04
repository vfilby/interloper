# warpgate-approver

Approve or deny agent requests from an iPhone, secured by a Secure Enclave key behind Face ID or an app PIN. Started
as Warpgate ticket approval (Claude and agent rw/admin SSH access). Now growing into a **clearing house** for agent
approvals: SSH tickets, held mail, scoped MCP leases (Paperless).

- Design and decisions: [docs/DESIGN.md](docs/DESIGN.md)
- Wire protocol (adapters, hub, app): [docs/PROTOCOL.md](docs/PROTOCOL.md)
- iOS app (native SwiftUI): [ios/README.md](ios/README.md)
- Phase 1 deploy (broker + Pushover on bastion): [docs/runbooks/deploy-phase1.md](docs/runbooks/deploy-phase1.md)
- Hub sign-in with Authelia (OIDC): [docs/runbooks/oidc.md](docs/runbooks/oidc.md)
- TestFlight beta of the iOS app: [docs/runbooks/testflight.md](docs/runbooks/testflight.md)
- The Warpgate/bastion side (bastion-ssh, bastion-ssh-ticket, hosts.toml `[approvers.approver]`, bastion-apply) lives in
  `infra/bastion`.

```
broker/cmd/broker        phase 1: poll Warpgate, policy, Pushover (deployed)
broker/cmd/wga-hub       clearing-house relay + management UI
broker/cmd/wga-adapter   one adapter per service (sources: demo, warpgate)
broker/cmd/wga-device    software stand-in for the phone (testing only)
ios/                     the app (XcodeGen; ApproverKit Swift package)
testdata/interop/        Go <-> CryptoKit fixtures
scripts/                 end-to-end tests (CLI device; real app in the simulator)
```

```
make test      # Go: vet + tests (race detector)
make ios-test  # ApproverKit: swift test
make e2e       # real binaries over loopback with the software device
make e2e-ui    # real app in the iOS simulator against a live hub and demo adapter
make dist      # tests, then deploy/broker for linux/arm64 (bastion)
```

Host names in the docs are placeholders: `*.home.example` stands for your internal domain and `192.0.2.x` for LAN
addresses. Put real values in local configuration (`broker.env`, flags), never in the repository: it is public.

Trust is per **user**. Each user has a device list (roster) signed by their own phones, and a new phone is approved on
an existing one with Face ID. Each adapter trusts a user once:
`wga-adapter trust add-user <user> <account fingerprint>`. The hub hands out enrollment codes but cannot add a device
to anyone.

Status:
- Phase 1 is live.
- The clearing-house skeleton is built and tested, on LAN only.
- Off-network transport is not chosen yet (see DESIGN.md, "Off-network transport").
