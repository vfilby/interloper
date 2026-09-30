# warpgate-approver

Approve or deny Warpgate ticket requests (Claude / agent rw & admin access) from an iPhone, secured by a Secure Enclave
key behind Face ID or an app PIN, working on or off the home network.

- Design and decisions: [docs/DESIGN.md](docs/DESIGN.md)
- Phase 1 deploy (broker + Pushover on bastion): [docs/runbooks/deploy-phase1.md](docs/runbooks/deploy-phase1.md)
- The Warpgate/bastion side (bastion-ssh, bastion-ssh-ticket, hosts.toml `[approvers.approver]`, bastion-apply) lives in
  `infra/bastion`.

```
make test    # vet + tests (race detector)
make dist    # tests, then deploy/broker for linux/arm64 (bastion)
```

Status: phase 1 built, not deployed.
