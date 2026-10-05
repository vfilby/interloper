# Warpgate adapter

Turns pending Warpgate **ticket requests** into approval requests on the phone, and approves or denies them in
Warpgate after a verified decision. It runs on the Warpgate host, beside Warpgate, and holds a Warpgate token that can
manage ticket requests and nothing else. How adapters work in general: [adapter/README.md](../../adapter/README.md).

```
source.go                package warpgate: the Source (pending requests -> items; approve/deny in Warpgate)
policy/                  denies, before anyone is asked, what is not allowed at all (unknown requesters, too long)
wgapi/                   the small part of Warpgate's admin API it uses (as of Warpgate 0.28.6)
cmd/interpose-adapter/   the binary: adapter/cli with the Warpgate source
deploy/                  Dockerfile, compose.yaml, adapter.env.default, install.sh (guided install on the host)
```

## Settings

From the environment (`deploy/adapter.env.default`, copied once to `/opt/interpose-adapter/.env`):

| Variable | Default | Meaning |
|---|---|---|
| `HUB_URL` | (required) | the hub's API base URL as the adapter reaches it |
| `WARPGATE_URL` | (required) | Warpgate's base URL |
| `WARPGATE_TOKEN_FILE` | `/run/secrets/warpgate-token` | the approver token |
| `ALLOWED_REQUESTERS` | (required) | Warpgate usernames that may ask for tickets, comma-separated; others are denied |
| `MAX_DURATION_RW`, `MAX_DURATION_ADMIN` | `2h` | longer tickets are denied without asking |
| `REQUEST_TTL` | `15m` | unanswered requests are **denied** at Warpgate after this (fail closed) |

## Deploying

The hub comes first: [docs/runbooks/deploy-clearing-house.md](../../docs/runbooks/deploy-clearing-house.md), section 1.
Container hardening and layout: [docs/docker.md](../../docs/docker.md).

### 1. A Warpgate approver token

The adapter needs a Warpgate API token that can approve and deny ticket requests (`ticket_requests_manage`) and do
nothing else: a dedicated Warpgate user with no credentials but that token, and no access roles. Give the adapter its
own user rather than sharing one, so it can be revoked alone.

### 2. Build the adapter and copy it to the Warpgate host

On your workstation, in this repository:
```
make dist-adapter        # runs the tests, then builds adapters/warpgate/deploy/interpose-adapter (linux/arm64); note the sha256
```
Copy `adapters/warpgate/deploy/` (`install.sh`, `Dockerfile`, `compose.yaml`, `adapter.env.default`,
`interpose-adapter`) and the Warpgate token (as a file named `warpgate-token`) into one directory on the adapter host,
e.g. `~/adapter-staging`.

The image is built on the host from that binary, not pulled from a registry: the binary you checked is the one that
runs.

### 3. Run the guided install

On the adapter host, in the staging directory:
```
cd ~/adapter-staging && sudo ./install.sh <sha256 from step 2>
```
Given the sha256, it checks the binary without asking (without it, it asks once per new binary). It runs start to
finish and, where it needs you, shows a **YOUR TURN** box, waits, and checks what you enter:
1. the hub's public URL and Warpgate's URL, if `.env` does not have them yet;
2. the Warpgate token, if you did not copy it over as `warpgate-token`;
3. registering the adapter: it shows the **public** key to paste into the hub's management UI (**Adapters**, id
   `warpgate`), then asks for the token the hub shows once;
4. the account to trust: user id and **account fingerprint, read off a phone on the account** (Device tab → the
   **Account** section → "Account fingerprint", 8 groups of 4; the 4-group one above it is the device's), never off
   the hub's page, since a hub that lies about it would get an account of its own trusted;
5. it starts the adapter, waits for it to report `started`, and shows the adapter fingerprint to compare on the phone
   (Device → **Check hub for new adapters**).

Running it again is safe and is also how you update: finished steps are skipped. Only real problems stop it, marked
`ERROR`.

### 4. Check end to end

File a Warpgate ticket request. Within seconds the phone gets a push ("Approval request") and the request shows
Warpgate's facts. Approve with Face ID; the ticket is approved in Warpgate, and the adapter log shows it.

### Updating

Steps 2 and 3 again; the install skips what is already set up (key, hub token, trust list).
