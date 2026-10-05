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

## 4. Settings, then install

On the adapter host, **before** running the install, make the settings file and set `HUB_URL` (the hub's public URL)
and `WARPGATE_URL`:
```
cd ~/adapter-staging
cp adapter.env.default .env && vi .env
sudo ./install.sh
```
It asks you to confirm the sha256 (compare with step 3), installs into `/opt/interpose-adapter`, builds the image,
prints the adapter's **public key** and **fingerprint**, and stops: no hub token yet.

## 5. Register the adapter at the hub

In the hub's management UI, as an admin: **Adapters** → id `warpgate`, the public key from step 4. The token is shown
once. On the adapter host:
```
printf '%s\n' '<token>' | sudo install -m 0400 -o 65533 -g 65533 /dev/stdin /opt/interpose-adapter/data/hub-token
```

## 6. Trust your account, then start

On the phone: **Device** tab → the **account fingerprint**. Read it off the phone, never off the hub's page: a hub
that lies about it would get an account of its own trusted. On the adapter host:
```
cd /opt/interpose-adapter && sudo docker compose run --rm --no-deps adapter-warpgate trust add-user -dir /data <user> <account fingerprint>
cd ~/adapter-staging && sudo ./install.sh     # second run: everything is in place, it starts the adapter
cd /opt/interpose-adapter && sudo docker compose logs -f
```
On the phone: Device → **Check hub for new adapters**; the `warpgate` fingerprint must match step 4's. Then delete
the staging directory (install.sh has already shredded the token copy).

## 7. Check end to end

File a Warpgate ticket request. Within seconds the phone gets a push ("Approval request") and the request shows
Warpgate's facts. Approve with Face ID; the ticket is approved in Warpgate, and the adapter log shows it.

## Updating

- **Hub:** rebuild from the new commit and restart it; its state directory carries over.
- **Adapter:** steps 3 and 4 again. Key, hub token and trust list stay in `/opt/interpose-adapter`.
