# warpgate-approver

Approve or deny Warpgate ticket requests (Claude / agent rw & admin access) from an iPhone, secured by a Secure Enclave
key behind Face ID or an app PIN, working on or off the home network.

- Design and decisions: [docs/DESIGN.md](docs/DESIGN.md)
- Phase 1 deploy (broker + Pushover on interloper): [docs/runbooks/deploy-phase1.md](docs/runbooks/deploy-phase1.md)
- The Warpgate/bastion side (cssh, cssh-ticket, hosts.toml `[approvers.approver]`, wg-apply) lives in
  `fnet-infrastructure/bastion`.

```
make test    # vet + tests (race detector)
make dist    # tests, then deploy/broker for linux/arm64 (interloper)
```

Status: phase 1 built, not deployed.
