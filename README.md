# Interpose

Approve or deny agent requests from an iPhone, secured by a Secure Enclave key behind Face ID or an app PIN. A
**clearing house** for agent approvals: SSH tickets (Warpgate), and later held mail and scoped MCP leases.

Three parts:
- **Interpose Hub** (`wga-hub`): a relay and management UI. It holds nothing that can act: requests are sealed for the
  user's phones, decisions are signed on them.
- **Adapters**, one beside each service it guards: they build the requests, verify every decision against their own
  trust list, and act.
- **The app** (Interloper, iOS): shows a request, asks for Face ID, signs the decision.

## Layout

```
ios/                  the app (SwiftUI, XcodeGen; ApproverKit Swift package)          ios/README.md
broker/               the hub (wga-hub) and the software phone for tests (wga-device)  broker/README.md
adapter/              how adapters work, the shared adapter core and command line,     adapter/README.md
                      and the reference adapter (wga-adapter-demo)
adapters/warpgate/    the Warpgate adapter (wga-adapter) and its guided install        adapters/warpgate/README.md
internal/             Go shared by all of the above: protocol (+ Go/Swift interop fixtures), audit log, software device
docs/                 design, wire protocol, Docker setup, runbooks
scripts/              end-to-end tests (CLI device; real app in the simulator)
SECURITY.md           security model and how to report a vulnerability
```

All Go is one module (`go.mod` at the root), so `go test ./...` covers the hub and every adapter.

## Documentation

- Design and decisions: [docs/DESIGN.md](docs/DESIGN.md)
- Wire protocol (adapters, hub, app): [docs/PROTOCOL.md](docs/PROTOCOL.md)
- Writing an adapter: [adapter/README.md](adapter/README.md)
- Running the hub and adapters in Docker: [docs/docker.md](docs/docker.md)
- Deploying end to end (hub, then an adapter): [docs/runbooks/deploy-clearing-house.md](docs/runbooks/deploy-clearing-house.md)
- Hub sign-in with OIDC: [docs/runbooks/oidc.md](docs/runbooks/oidc.md)
- iOS app: [ios/README.md](ios/README.md); TestFlight: [docs/runbooks/testflight.md](docs/runbooks/testflight.md)
- Security model and reporting: [SECURITY.md](SECURITY.md)

## Develop

```
make check         # what CI runs: gofmt, vet, tests (race detector), CLI end to end
make test          # Go: vet + tests
make e2e           # real binaries over loopback with the software device
make ios-test      # ApproverKit: swift test
make e2e-ui        # real app in the iOS simulator against a live hub and the reference adapter
make build         # every Go command into bin/
make dist-adapter  # tests, then adapters/warpgate/deploy/wga-adapter for linux/arm64
make docker-hub    # the hub's container image
```

### Pull requests and CI

`main` is protected: changes land through pull requests. [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs
on every push and every pull request:

| Job | What |
|---|---|
| Go | gofmt, `go mod tidy`, vet, tests with the race detector, `scripts/e2e-cli.sh`, cross-builds for linux/arm64 and amd64 |
| Docker | builds the hub image and the Warpgate adapter image, checks the adapter's compose file and install script |
| ApproverKit | `swift test`, including the Go ↔ CryptoKit interop fixtures |
| govulncheck | known vulnerabilities in dependencies and the Go standard library (informational, not required) |
| **CI ok** | passes only if Go, Docker and ApproverKit passed: the one check branch protection requires |

Open a pull request and turn on auto-merge; it merges once CI is green:

```
gh pr create --fill && gh pr merge --auto --squash --delete-branch
```

Enable auto-merge from your own account (as above), not from a workflow: a merge made by the workflow token does not
start other workflows, so the TestFlight upload on `main` would not run.

One-time repository settings (admin):

```
gh api -X PATCH repos/vfilby/interloper -F allow_auto_merge=true -F delete_branch_on_merge=true
gh api -X PUT repos/vfilby/interloper/private-vulnerability-reporting    # SECURITY.md's reporting channel
gh api -X PUT repos/vfilby/interloper/branches/main/protection --input - <<'EOF'
{"required_status_checks": {"strict": false, "checks": [{"context": "CI ok"}]},
 "required_pull_request_reviews": {"required_approving_review_count": 0},
 "enforce_admins": true, "restrictions": null,
 "required_linear_history": true, "allow_force_pushes": false, "allow_deletions": false}
EOF
```

What that protection means for `main`:
- every change arrives through a pull request (no approving review needed, so you can merge your own);
- the pull request merges only once **CI ok** has passed; `strict: false` means it need not be rebased on the latest
  `main` first;
- the rules bind admins too (`enforce_admins`): no direct pushes, not even by the owner;
- history stays linear (squash merges), and `main` cannot be force-pushed or deleted. To allow force pushes later, set
  `allow_force_pushes` to `true` and run the same command again.

Tags are not covered, so the TestFlight workflow can still push its `ios/v*` tags.

## Notes

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
