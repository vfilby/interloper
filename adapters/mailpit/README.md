# Mail adapter (Mailpit)

Turns mail that a [Mailpit](https://mailpit.axllent.org) relay is **holding** into approval requests on the phone,
and releases a message to exactly the recipients shown after a verified approval. It runs on the Mailpit host, beside
Mailpit, and holds a Mailpit login. How adapters work in general: [adapter/README.md](../../adapter/README.md).

```
source.go                         package mailpit: the Source (held messages -> items; release / tag in Mailpit)
mpapi/                            the small part of Mailpit's REST API it uses (as of Mailpit 1.31)
cmd/interpose-adapter-mailpit/    the binary: adapter/cli with the Mailpit source
deploy/                           Dockerfile, compose.yaml, adapter.env.default, install.sh (guided install on the host)
```

## Where it sits

```
agent ─SMTP─> Mailpit (holds everything) ─webhook─> auto-release gate ──every recipient on its allow-list──> released
                                                         │
                                                         └─otherwise: tag `held` ──> this adapter ──> phone
                                                                                        │
                                                approve: release to the recipients shown, tag `approved-sent`
                                                deny / unanswered: tag `denied` (the message stays in Mailpit)
```

The adapter does not replace the allow-list. A gate in front of it (any webhook receiver that tags what it does not
send) decides what goes out unasked; the adapter asks about everything the gate tagged `held` and nothing else. A
message the gate never saw (gate down) carries no tag and simply waits in Mailpit's UI, as before.

Each outcome is a tag on the message, so Mailpit's UI shows what happened and nothing is asked about or sent twice:

| Tags | Meaning |
|---|---|
| `held` | waiting; the only state the adapter asks about |
| `held`, `approving` | approved; set **before** the release, so a crash mid-release can never send it again |
| `held`, `approved-sent` | released to the recipients shown |
| `held`, `send-failed` | the release failed (the phone shows the error); retry by hand in the UI |
| `held`, `denied` | denied on the phone, unanswered within `REQUEST_TTL`, or not describable exactly |

Denying never deletes: the person can still release a denied message by hand in Mailpit's UI.

## What the phone shows

Everything comes from Mailpit's stored copy, the bytes a release would send: From, each To / Cc / Bcc (Bcc holds the
envelope recipients missing from the headers), Reply-To, Subject, each attachment with its type and decoded size, a
body excerpt, and the message size. Risk is `elevated` when there are attachments (the app then wants a deliberate
gesture), else `normal`. There is no `reason`: the agent's explanation, if any, is the mail itself.

Approve releases to To + Cc + Bcc, lowercased and de-duplicated, which is exactly the set shown. A message whose
recipients or MIME structure cannot be stated exactly is denied without asking. A Mailpit read error is never a
denial; the adapter retries on the next poll.

The adapter never opens a message through `GET /api/v1/message/{ID}` (that marks it read); held mail stays unread.

## Settings

From the environment (`deploy/adapter.env.default`, copied once to `/opt/interpose-adapter-mailpit/.env`):

| Variable | Default | Meaning |
|---|---|---|
| `HUB_URL` | (required) | the hub's API base URL as the adapter reaches it |
| `ADAPTER_ID` | `mail` | the id registered at the hub; one adapter per Mailpit instance |
| `MAILPIT_URL` | `http://127.0.0.1:8025` | Mailpit's API (the container uses the host network) |
| `MAILPIT_USER` | (required) | the adapter's own login in Mailpit's `ui-users` file |
| `MAILPIT_PASSWORD_FILE` | `/run/secrets/mailpit-password` | its password (install.sh makes one) |
| `MAX_AGE` | `24h` | held messages older than this are left alone, so the backlog is not paged at install |
| `REQUEST_TTL` | `12h` | unanswered requests are tagged `denied` after this (fail closed); keep it below `MAX_AGE` |

## The credential

Mailpit has one kind of login: whoever has it can read, release, tag and delete every message in that instance. Give
the adapter its own line in `ui-users` (install.sh prints it) so it can be removed alone, and keep the instance's API
reachable only from loopback and the reverse proxy. The adapter itself listens on nothing.

## Deploying

The hub comes first: [docs/runbooks/deploy-clearing-house.md](../../docs/runbooks/deploy-clearing-house.md), section 1.

1. On your workstation: `make dist-adapter-mailpit` (tests, then `deploy/interpose-adapter-mailpit` for linux/amd64;
   `MAILPIT_ARCH=arm64` for an ARM host). Note the sha256.
2. Copy `adapters/mailpit/deploy/` (with the binary) to a staging directory on the Mailpit host.
3. `cd ~/adapter-mailpit-staging && sudo ./install.sh <sha256>`. As with the Warpgate adapter, it is guided and
   re-runnable; where it needs you it shows a **YOUR TURN** box:
   1. the hub's public URL;
   2. the adapter's Mailpit login: it makes a password and prints the `ui-users` line to add, then waits until
      Mailpit accepts it (recreate the Mailpit container after editing the file);
   3. registering the adapter at the hub (id `mail` unless `ADAPTER_ID` says otherwise) and pasting the hub token;
   4. the account to trust, read off the phone;
   5. start, and the adapter fingerprint to compare on the phone.
4. Send a message to an address the gate does not auto-send to. The phone gets "Email bob@… " within seconds;
   approve, and the message is released and tagged `approved-sent`.

Updating: steps 1–3 again; finished steps are skipped.
