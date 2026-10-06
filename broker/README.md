# Broker: the Interpose Hub

`interpose-hub` is the clearing house's relay and management UI. It holds **nothing that can act**: adapters seal
requests to users' phones and verify the phones' signed decisions themselves. A compromised hub can drop or delay
requests; it cannot approve, forge or read them ([SECURITY.md](../SECURITY.md)).

```
cmd/interpose-hub/      the hub
cmd/interpose-device/   a software stand-in for the phone, for tests and CLI use (keys in a file: never trust it on a
                        real adapter)
internal/hub/           API, management UI (server-rendered, no JavaScript), OIDC sign-in, store, APNs wake-ups
internal/apns/          APNs client (token auth)
e2e/                    in-process end-to-end tests: a real hub, the adapter core with the demo source, software phones
Dockerfile              container image, built from source (docs/docker.md)
```

The hub shares the wire protocol, audit log and software device with the adapters through `../internal`.

## What it does

- Stores sealed requests, queues signed decisions, keeps signed acks.
- Hands out one-time enrollment codes (QR) and stores each user's roster chain. It cannot add a device to anyone:
  rosters are signed by the user's own phones.
- Sends APNs wake-ups with fixed text ("Approval request", "New device"), never request content.
- Management UI: enrollment, devices (card download, revoke), adapters (register, remove), pending metadata, audit log.

## Running

Two listeners:

| Flag | Default | |
|---|---|---|
| `-api` | `127.0.0.1:8740` | devices and adapters; the reverse proxy sends `/v1/*` and `/healthz` here |
| `-admin` | `127.0.0.1:8741` | management UI; everything else goes here |
| `-url` | `http://127.0.0.1:8740` | the API base URL as phones reach it (goes into enrollment links); must be https when `-api` is not loopback |
| `-state` | `hub-data` | state directory: `state.json`, `audit.jsonl`, `session.key` |
| `-oidc-issuer`, `-oidc-client-id`, `-oidc-secret-file`, `-oidc-redirect`, `-oidc-admin-group` | | OIDC sign-in ([docs/runbooks/oidc.md](../docs/runbooks/oidc.md)) |
| `-apns-key-file`, `-apns-key-id`, `-apns-team-id`, `-apns-topic` | | APNs wake-ups ([docs/runbooks/testflight.md](../docs/runbooks/testflight.md), step 5) |

Without `-oidc-issuer` there is no sign-in (everyone is an admin), so the hub refuses to start unless the management UI
listens on loopback only. That is the local development mode:

```
go run ./broker/cmd/interpose-hub          # API on http://127.0.0.1:8740, management UI on http://127.0.0.1:8741
```

The hub speaks plain HTTP. So that bearer tokens and enrollment codes never cross a network in the clear, it refuses to
start when `-api` is not a loopback address and `-url` is not https (a reverse proxy terminating TLS in front of it),
or when `-oidc-redirect` is http on a host other than loopback.

In production, run it behind a reverse proxy that terminates TLS, with OIDC: see
[docs/runbooks/deploy-clearing-house.md](../docs/runbooks/deploy-clearing-house.md) and, for containers,
[docs/docker.md](../docs/docker.md). `GET /healthz` answers `ok`.

## Testing

```
go test ./broker/...    # hub unit tests and the in-process end to end
make e2e                # real binaries over loopback (scripts/e2e-cli.sh)
```
