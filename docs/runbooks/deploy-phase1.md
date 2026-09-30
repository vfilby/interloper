# Deploy phase 1: broker + Pushover on interloper

The person runs all of this. Claude has no login on interloper, by design: the broker's Warpgate token can approve
any pending request, and interloper is the one host no agent can reach.

What phase 1 does: every ~5 s it lists pending ticket requests and notifies Pushover (requester, host, tier, duration,
and the requester's own reason, labelled as theirs). It applies the policy (allowed requesters, rw/admin tiers only,
duration caps, 15 min expiry). In `report` mode it only flags what it would deny; in `enforce` it denies those itself.
Approval stays in the Warpgate admin UI. It alerts when Warpgate has been unreachable for 5 min, and 30 days before
its token expires.

Layout on interloper:

```
/opt/warpgate-approver/            root:root 0755
  compose.yaml, Dockerfile         root:root 0644
  broker                           root:root 0755  (static linux/arm64, built on the Mac)
  secrets/                         65532:65532 0700
    warpgate-token                 65532:65532 0400  approver user's API token
    pushover-token                 65532:65532 0400  Pushover application token
    pushover-user                  65532:65532 0400  Pushover user key
  data/                            65532:65532 0700  state.json, audit.jsonl
```

## 0. Pushover application (once)

On https://pushover.net/apps/build create an application `warpgate-approver`. Note its **API token**, and your
**user key** from the Pushover dashboard.

## 1. Build and stage (on the Mac)

`$REPO` is the checkout holding this file.

```fish
cd $REPO; and make dist            # runs the tests, prints the binary's sha256
ssh vfilby@192.0.2.12 'umask 077; mkdir -p ~/wga-staging/deploy'
tar -C deploy -cf - Dockerfile compose.yaml broker | ssh vfilby@192.0.2.12 'tar -C ~/wga-staging/deploy -xf -'
```

Secrets go through pipes into files only you can read; nothing lands in shell history or on the Mac's disk.

```fish
# copy the Pushover API token to the clipboard, then:
pbpaste | ssh vfilby@192.0.2.12 'umask 077; cat > ~/wga-staging/pushover-token'
# copy your Pushover user key to the clipboard, then:
pbpaste | ssh vfilby@192.0.2.12 'umask 077; cat > ~/wga-staging/pushover-user'
# the approver's Warpgate token (admin password + OTP prompt; the token goes straight into the pipe):
wg-apply --mint-token approver | ssh vfilby@192.0.2.12 'umask 077; cat > ~/wga-staging/warpgate-token'
pbcopy < /dev/null                 # clear the clipboard
```

## 2. Install (on interloper)

```sh
ssh -t vfilby@192.0.2.12
sha256sum ~/wga-staging/deploy/broker          # must match what make dist printed
sudo install -d -m 0755 -o root -g root /opt/warpgate-approver
sudo install -d -m 0700 -o 65532 -g 65532 /opt/warpgate-approver/secrets /opt/warpgate-approver/data
sudo install -m 0644 -o root -g root ~/wga-staging/deploy/Dockerfile ~/wga-staging/deploy/compose.yaml /opt/warpgate-approver/
sudo install -m 0755 -o root -g root ~/wga-staging/deploy/broker /opt/warpgate-approver/
sudo install -m 0400 -o 65532 -g 65532 ~/wga-staging/warpgate-token ~/wga-staging/pushover-token \
  ~/wga-staging/pushover-user /opt/warpgate-approver/secrets/
shred -u ~/wga-staging/warpgate-token ~/wga-staging/pushover-token ~/wga-staging/pushover-user
rm -r ~/wga-staging

cd /opt/warpgate-approver
sudo docker compose build
sudo docker compose run --rm broker -check-config     # "configuration ok"
sudo docker compose run --rm broker -once             # one real poll; no ERROR/WARN lines expected
sudo docker compose up -d
sudo docker compose logs -f                           # "started", then quiet
```

## 3. Test

From a Claude session (or ask Claude), file two harmless requests and deny both in the admin UI afterwards:

```sh
cssh-ticket ensure n-rw --desc "warpgate-approver phase-1 test: deny this" --timeout 60
cssh-ticket ensure n-rw --duration 14400 --desc "warpgate-approver phase-1 test: over the cap" --timeout 60
```

Expect within seconds:
- first: "claude wants RW on n", Duration 2h, the reason quoted, and a link to the tickets page;
- second: the same, headed "POLICY WOULD DENY: asks for 4h, over the 2h cap for rw (report mode)".

Then `sudo cat /opt/warpgate-approver/data/audit.jsonl` shows `seen`, `notified` and, once denied, `left-pending`.

## 4. Switch to enforce (after a few days of report mode that matched your own judgement)

Set `POLICY_MODE: enforce` in `compose.yaml`, then `sudo docker compose up -d`. From then on, policy violations are
denied with a reason starting `warpgate-approver:` (cssh prints it), and unanswered requests are denied after 15 min.

## Update

`make dist` on the Mac, stage `deploy/` as in step 1 (no secrets), then on interloper install the new files as in
step 2 and `sudo docker compose up -d --build`. Restarting the broker never restarts Warpgate (separate project).

## Stop / kill switch

- Stop watching: `cd /opt/warpgate-approver && sudo docker compose down`.
- Take its power away: Warpgate admin UI > Users > `approver` > delete its API token (or remove admin role
  `ticket-approver`). The broker then alerts that its token was rejected.

## Notes

- Egress: HTTPS to `interloper.home.example` (Warpgate, via the host) and `api.pushover.net`. Nothing listens.
- Pushover sees names, durations and reasons in plain text. Acceptable for this stopgap; APNs replaces it in phase 4.
- Memory: `GOMEMLIMIT=32MiB` in the image, `mem_limit: 64m` in compose. State is bounded by the number of pending
  requests; the audit log grows by a few hundred bytes per request.
- The approver token can also *read* Warpgate's user and target lists (0.28.6 allows that to any admin role). The
  broker needs them because ticket requests carry ids only. They hold no secrets.
