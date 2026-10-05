# Deploying the clearing house: a hub, and an adapter beside each service

Where things run, and why:
- **The hub** (`wga-hub`) runs behind your reverse proxy, which terminates TLS, and signs people in with your OIDC
  provider (`oidc.md`). It holds nothing that can act, so it can sit apart from the services it serves.
- **Each adapter** runs **beside the service it guards**, e.g. the Warpgate adapter on the Warpgate host. It holds that
  service's credential and its own trust list. Owning that host already owns the service, so keeping them there adds
  no new place to steal approval from. An adapter only connects out: to the hub and to its service.

Host names below are placeholders (`hub.home.example`, `warpgate.home.example`, the "adapter host"); use your own.

## 1. The hub

Build `wga-hub` (`broker/cmd/wga-hub`) into a container, or run the binary. It needs:
- **a state directory** (`-state`), writable, private to the hub;
- **the reverse proxy** sending `/v1/*` and `/healthz` to the API listener (`-api`, default `:8740`) and everything
  else to the management UI (`-admin`, default `127.0.0.1:8741`; `0.0.0.0:8741` with OIDC). `-url` is the public base
  URL, e.g. `https://hub.home.example`;
- **OIDC** for the management UI and phone sign-in (`oidc.md`): `-oidc-issuer`, `-oidc-client-id`,
  `-oidc-secret-file`, `-oidc-redirect`, `-oidc-admin-group`;
- **optionally APNs** for wake-up pushes (`testflight.md` step 5): `-apns-key-file`, `-apns-key-id`.

Check: `https://hub.home.example/healthz` says `ok`; signing in shows you as admin.

## 2. A Warpgate approver token for the adapter

The adapter needs a Warpgate API token that can approve and deny ticket requests (`ticket_requests_manage`) and do
nothing else: a dedicated Warpgate user with no credentials but that token, and no access roles. Give the adapter its
own user rather than sharing one, so it can be revoked alone.

## 3. Build the adapter and copy it to the service's host

On your workstation, in this repository:
```
make dist-adapter        # runs the tests, then builds deploy/adapter/wga-adapter (linux/arm64); note the sha256
```
Copy `deploy/adapter/` (`install.sh`, `Dockerfile`, `compose.yaml`, `adapter.env.default`, `wga-adapter`) and the
Warpgate token (as a file named `warpgate-token`) into one directory on the adapter host, e.g. `~/adapter-staging`.

## 4. Run the guided install

On the adapter host, in the staging directory:
```
cd ~/adapter-staging && sudo ./install.sh <sha256 from step 3>
```
Given the sha256, it checks the binary without asking (without it, it asks once per new binary). It runs start to finish and, where it needs you, shows a **YOUR TURN** box, waits, and checks what you enter:
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

## 5. Check end to end

File a Warpgate ticket request. Within seconds the phone gets a push ("Approval request") and the request shows
Warpgate's facts. Approve with Face ID; the ticket is approved in Warpgate, and the adapter log shows it.

## Updating

- **Hub:** rebuild from the new commit and restart it; its state directory carries over.
- **Adapter:** steps 3 and 4 again; the install skips what is already set up (key, hub token, trust list).
