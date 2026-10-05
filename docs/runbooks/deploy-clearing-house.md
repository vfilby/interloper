# Deploying the clearing house: hub on n, Warpgate adapter on interloper

Where things run, and why:
- **Hub** on **n**, as the DockerStacks stack `interpose-hub`, behind the reverse proxy and its Authelia (OIDC), at
  `https://interpose-hub.home.example`. It holds nothing that can act, so it sits apart from what it guards.
- **Warpgate adapter** on **interloper**, beside Warpgate, in `/opt/interpose-adapter` (`deploy/adapter/`). It holds
  the Warpgate approver token and the trust list: owning interloper already owns Warpgate, so keeping them there adds
  no new place to steal approval from. It only connects out: to the hub and to Warpgate.
- **The phase-1 broker** keeps running (Pushover). Both watch the same ticket requests; whichever acts first wins, and
  the other sees the request resolved. Note `REQUEST_TTL` in the adapter: unanswered requests are **denied** after it.

Host names below are placeholders; the real ones are in the DockerStacks stack and your local `.env` files.

## 1. Hub (n)

Follow `DockerStacks/interpose-hub/README.md`: LLDAP groups, the OIDC client secret, the Authelia client, DNS, then
deploy. Check: `https://interpose-hub.home.example/healthz` says `ok`, and signing in shows you as admin.

## 2. The adapter's Warpgate token (Mac)

The adapter has its own Warpgate approver, `interpose-adapter` (`fnet-infrastructure/bastion/hosts.toml`): same
rights as the phase-1 `approver` (approve or deny ticket requests, nothing else), its own token, so either can be
revoked alone.
```
wg-apply --plan && wg-apply
wg-apply --mint-token interpose-adapter | ssh <you>@<interloper> 'umask 077; mkdir -p ~/interpose-staging; cat > ~/interpose-staging/warpgate-token'
```

## 3. Install the adapter (interloper)

On the Mac: `make dist-adapter` (tests, then `deploy/adapter/wga-adapter` for linux/arm64; note the sha256), then copy
`deploy/adapter/` to `~/interpose-staging` on interloper. There:
```
cd ~/interpose-staging && sudo ./install.sh
```
The first run creates `/opt/interpose-adapter/.env` and stops: set `HUB_URL` and `WARPGATE_URL`, run it again. It
prints the adapter's public key and fingerprint and stops again until steps 4 and 5 are done.

## 4. Register the adapter at the hub

In the hub's management UI, **Adapters**: id `warpgate`, the public key from step 3. The token is shown once:
```
printf '%s\n' '<token>' | sudo install -m 0400 -o 65533 -g 65533 /dev/stdin /opt/interpose-adapter/data/hub-token
```

## 5. Trust your account

Enroll a phone at the hub (app: Sign in, `https://interpose-hub.home.example`). Read the **account fingerprint off the
phone** (Device tab), never off the hub's page: a hub that lies about it would get an account of its own trusted.
```
cd /opt/interpose-adapter && sudo docker compose run --rm --no-deps adapter-warpgate trust add-user -dir /data <user> <account fingerprint>
sudo ./install.sh   # from ~/interpose-staging: now it starts the adapter
```
On the phone: Device → Check hub for new adapters; compare the `warpgate` fingerprint with step 3's.

## 6. Check end to end

File a ticket request the usual way (e.g. a `cssh … -rw` command). Within seconds: a push ("Approval request") and
the request in the app, with Warpgate's facts. Approve with Face ID; the adapter log shows it and the ticket is
approved in Warpgate. `sudo docker compose logs -f` in `/opt/interpose-adapter`.

## Updating

- **Hub:** new commit SHA in `DockerStacks/interpose-hub/compose.yaml`, then deploy that stack.
- **Adapter:** `make dist-adapter`, copy `deploy/adapter/`, `sudo ./install.sh`. Key, hub token and trust list stay.
