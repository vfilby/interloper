# Interpose

Approve or deny agent requests from an iPhone, secured by a Secure Enclave key behind Face ID or an app PIN. A
**clearing house** for agent approvals: SSH tickets (Warpgate), and later held mail and scoped MCP leases.

Three parts:
- **Interpose Hub** (`wga-hub`): a relay and management UI. It holds nothing that can act: requests are sealed for the
  user's phones, decisions are signed on them.
- **Adapters** (`wga-adapter`), one beside each service it guards: they build the requests, verify every decision
  against their own trust list, and act.
- **The app** (Interloper, iOS): shows a request, asks for Face ID, signs the decision.

- Design and decisions: [docs/DESIGN.md](docs/DESIGN.md)
- Wire protocol (adapters, hub, app): [docs/PROTOCOL.md](docs/PROTOCOL.md)
- Deploying the hub and an adapter: [docs/runbooks/deploy-clearing-house.md](docs/runbooks/deploy-clearing-house.md)
- Hub sign-in with OIDC: [docs/runbooks/oidc.md](docs/runbooks/oidc.md)
- iOS app (native SwiftUI): [ios/README.md](ios/README.md); TestFlight: [docs/runbooks/testflight.md](docs/runbooks/testflight.md)

```
broker/cmd/wga-hub       the hub: relay, management UI, APNs wake-ups
broker/cmd/wga-adapter   one adapter per service (sources: demo, warpgate)
broker/cmd/wga-device    software stand-in for the phone (testing only)
ios/                     the app (XcodeGen; ApproverKit Swift package)
deploy/adapter/          container and guided install for an adapter
testdata/interop/        Go <-> CryptoKit fixtures
scripts/                 end-to-end tests (CLI device; real app in the simulator)
```

```
make test          # Go: vet + tests (race detector)
make ios-test      # ApproverKit: swift test
make e2e           # real binaries over loopback with the software device
make e2e-ui        # real app in the iOS simulator against a live hub and demo adapter
make dist-adapter  # tests, then deploy/adapter/wga-adapter for linux/arm64
```

Host names in the docs are placeholders: `*.home.example` stands for your internal domain and `192.0.2.x` for LAN
addresses. Put real values in local configuration (`.env`, flags), never in the repository: it is public.

Trust is per **user**. Each user has a device list (roster) signed by their own phones, and a new phone is approved on
an existing one with Face ID. Each adapter trusts a user once:
`wga-adapter trust add-user <user> <account fingerprint>`. The hub hands out enrollment codes but cannot add a device
to anyone.

Status:
- In use for Warpgate tickets, on LAN/VPN, with APNs wake-ups. Phase 1 (a single broker that sent Pushover links to
  Warpgate's own UI) is retired.
- Off-network transport is not chosen yet (see DESIGN.md, "Off-network transport").
