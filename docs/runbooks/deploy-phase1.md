# Deploy phase 1: broker + Pushover on bastion

You run all of this. Claude has no login on bastion, by design: the broker's Warpgate token can approve any
pending request, and bastion is the one host no agent can reach.

Each step says **where** its commands run:
- **Mac**: a terminal on your Mac (fish is fine; every command below works in fish).
- **bastion**: after `ssh -t admin@192.0.2.12`, your own port-22 login on the bastion.

The checkout used below is `REPO=/Users/you/Projects/warpgate-approver/.claude/worktrees/phase1-broker`
(branch `worktree-phase1-broker`). If you merged that branch into `~/Projects/warpgate-approver`, use that instead.

## What gets installed

`deploy/` in the repo holds everything that goes to bastion:

| file in `deploy/` | what it is |
|---|---|
| `install.sh` | the installer; you run it with sudo on bastion (step 4) |
| `Dockerfile` | the container image: the `broker` binary on distroless, non-root |
| `compose.yaml` | the service definition (hardening, mounts, restart policy) |
| `broker.env.default` | default settings; becomes `/opt/warpgate-approver/broker.env` on the first install |
| `broker` | the program, built by `make dist` (step 1); not in git |

`install.sh` puts them here:

```
/opt/warpgate-approver/            root, 0755
  Dockerfile, compose.yaml         root, 0644   replaced on every install
  broker                           root, 0755   replaced on every install
  broker.env                       root, 0644   your settings: created once, never overwritten
  secrets/                         65532, 0700  (65532 = the container's user)
    warpgate-token                 65532, 0400  the approver user's Warpgate API token
    pushover-token                 65532, 0400  the Pushover application's API token
    pushover-user                  65532, 0400  your Pushover user key
  data/                            65532, 0700  state.json, audit.jsonl
```

## First install

### 1. Build (Mac)

```fish
cd /Users/you/Projects/warpgate-approver/.claude/worktrees/phase1-broker
make dist
```

You should see four `ok  warpgate-approver/broker/...` lines, then one line with a 64-character hex string followed by
`deploy/broker`. That string is the binary's sha256. **Keep it visible**: step 4 asks you to compare it.

### 2. Copy `deploy/` to bastion (Mac)

This makes a private directory `~/wga-staging` in your home on bastion and copies all five files of `deploy/`
into it. (Not straight into `/opt`: that is root's, and sudo cannot ask for a password through a pipe.)

```fish
ssh admin@192.0.2.12 'rm -rf ~/wga-staging && mkdir -m 700 ~/wga-staging'
tar -C deploy -cf - install.sh Dockerfile compose.yaml broker.env.default broker | ssh admin@192.0.2.12 'tar -C ~/wga-staging -xf - && ls -l ~/wga-staging'
```

The listing should show `Dockerfile`, `broker`, `broker.env.default`, `compose.yaml` and `install.sh`.

### 3. Put the three secrets next to them (Mac)

First, if you have not yet: on https://pushover.net/apps/build create an application named `warpgate-approver`; its
page shows the **API Token**. Your **User Key** is on the https://pushover.net dashboard.

Each command below writes one secret into a file only you can read in `~/wga-staging`. Nothing is echoed, lands in
shell history, or is written on the Mac.

```fish
# 3a. Copy the Pushover API Token to the clipboard, then:
pbpaste | ssh admin@192.0.2.12 'umask 077; cat > ~/wga-staging/pushover-token'

# 3b. Copy your Pushover User Key to the clipboard, then:
pbpaste | ssh admin@192.0.2.12 'umask 077; cat > ~/wga-staging/pushover-user'

# 3c. Mint the approver's Warpgate token. bastion-apply asks for the Warpgate admin username, password and one-time code;
#     the token goes straight into the pipe.
bastion-apply --mint-token approver | ssh admin@192.0.2.12 'umask 077; cat > ~/wga-staging/warpgate-token'

# 3d. Clear the clipboard.
pbcopy < /dev/null
```

3c should end with `API token for approver minted, expires ...` and `temporary password deleted from approver`.

### 4. Run the installer (bastion)

```sh
ssh -t admin@192.0.2.12
cd ~/wga-staging
sudo ./install.sh
```

The installer:
1. shows the binary's sha256 and asks whether it matches step 1 (answer `y`);
2. checks all three secrets are there, else stops **before changing anything**;
3. installs the files into `/opt/warpgate-approver` with the owners and modes above, and shreds the secret copies
   in `~/wga-staging`;
4. builds the image, checks the configuration (`configuration ok`), and polls Warpgate once for real (`poll ok`);
   if that poll fails it stops and does **not** start the service;
5. starts the service and shows `docker compose ps` (state `running`).

Then, still on bastion:

```sh
rm -rf ~/wga-staging
cd /opt/warpgate-approver && sudo docker compose logs -f     # a "started" line, then quiet; Ctrl-C to leave
```

### 5. Test (Mac)

File two harmless requests (or ask Claude to). Each waits 60 s, then gives up; the request stays pending.

```fish
bastion-ssh-ticket ensure files-01-rw --desc "warpgate-approver phase-1 test: deny this" --timeout 60
bastion-ssh-ticket ensure files-01-rw --duration 14400 --desc "warpgate-approver phase-1 test: over the cap" --timeout 60
```

Within seconds of each, Pushover should show:
- first: **claude wants RW on n**: `Target: files-01-rw`, `Duration: 2h`, the reason in quotes, and a link to the tickets page;
- second: the same with **POLICY WOULD DENY: asks for 4h, over the 2h cap for rw (report mode)** at the top.

(The second is filed only after the first is resolved: Warpgate allows one pending request per user and target. So
deny the first in the admin UI, run the second, then deny that too.)

Check the audit log (bastion):

```sh
sudo cat /opt/warpgate-approver/data/audit.jsonl
```

For each request: a `seen`, a `notified` and, after you denied it, a `left-pending` line.

## Switch to enforce (bastion, after a few days of report mode that matched your judgement)

```sh
sudo sed -i 's/^POLICY_MODE=report$/POLICY_MODE=enforce/' /opt/warpgate-approver/broker.env
grep POLICY_MODE /opt/warpgate-approver/broker.env        # POLICY_MODE=enforce
cd /opt/warpgate-approver && sudo docker compose up -d
```

From then on, policy violations are denied with a reason starting `warpgate-approver:` (bastion-ssh prints it), and
requests left unanswered for 15 min are denied.

## Update to a new version

Steps 1, 2 and 4 only: no secrets needed, the installed ones and your `broker.env` are kept. The installer says so
for each. Restarting the broker never restarts Warpgate (separate compose project).

## Stop / kill switch

- Stop watching (bastion): `cd /opt/warpgate-approver && sudo docker compose down`
- Take its power away: Warpgate admin UI > Users > `approver` > delete its API token (or remove its admin role
  `ticket-approver`). If the broker is still running, it alerts after 5 min that its token was rejected.

## Notes

- Egress: HTTPS to `bastion.home.example` (Warpgate, through the host) and `api.pushover.net`. Nothing listens.
- Pushover sees names, durations and reasons in plain text. Acceptable for this stopgap; APNs replaces it in phase 4.
- Memory: `GOMEMLIMIT=32MiB` in the image, `mem_limit: 64m` in compose.
- The approver token can also *read* Warpgate's user and target lists (0.28.6 allows that to any admin role). The
  broker needs them because ticket requests carry ids only. They hold no secrets.
