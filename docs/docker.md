# Docker setup

Both the hub and the adapters run as small static Go binaries on `distroless/static` (no shell, no package manager),
as non-root users, with read-only root filesystems. Host names here are placeholders; put real ones in `.env` files on
the host, never in the repository.

| | Image | Built from | Where it runs |
|---|---|---|---|
| Hub | `interpose-hub` | source: [`broker/Dockerfile`](../broker/Dockerfile) | anywhere behind your reverse proxy |
| Warpgate adapter | `interpose-adapter` | a checked binary: [`adapters/warpgate/deploy/Dockerfile`](../adapters/warpgate/deploy/Dockerfile) | on the Warpgate host |

CI builds both images on every pull request; nothing is pushed to a registry.

## The hub

Build from the repository root (the Dockerfile needs the whole Go module):

```
make docker-hub          # = docker build -f broker/Dockerfile -t interpose-hub:local .
```

For a different architecture than the build machine: `docker buildx build --platform linux/arm64 -f broker/Dockerfile ...`.

Example `compose.yaml` on the hub's host (e.g. `/opt/interpose-hub`), with OIDC ([runbooks/oidc.md](runbooks/oidc.md))
and APNs ([runbooks/testflight.md](runbooks/testflight.md), step 5):

```yaml
name: interpose-hub

services:
  hub:
    image: interpose-hub:local
    restart: unless-stopped
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 128m
    pids_limit: 64
    command:
      - -api=0.0.0.0:8740
      - -admin=0.0.0.0:8741        # allowed only with OIDC; without it the hub insists on loopback
      - -url=${HUB_URL:?set HUB_URL in .env}
      - -oidc-issuer=${OIDC_ISSUER:?set OIDC_ISSUER in .env}
      - -oidc-client-id=interpose
      - -oidc-secret-file=/run/secrets/oidc-secret
      - -oidc-redirect=${ADMIN_URL:?set ADMIN_URL in .env}/oidc/callback
      - -apns-key-file=/run/secrets/apns.p8
      - -apns-key-id=${APNS_KEY_ID:?set APNS_KEY_ID in .env}
    env_file: [.env]
    ports:
      - "127.0.0.1:8740:8740"      # only the reverse proxy should reach these
      - "127.0.0.1:8741:8741"
    volumes:
      - ./data:/data               # state.json, audit.jsonl, session.key
      - ./secrets/oidc-secret:/run/secrets/oidc-secret:ro
      - ./secrets/apns.p8:/run/secrets/apns.p8:ro
    logging:
      driver: json-file
      options: {max-size: "5m", max-file: "3"}
```

`.env` beside it:

```
TZ=America/Los_Angeles
HUB_URL=https://hub.home.example        # the API as phones reach it
ADMIN_URL=https://hub-admin.home.example
OIDC_ISSUER=https://sso.home.example
APNS_KEY_ID=ABC123DEFG
```

Before the first start:

```
mkdir -p data secrets && chown 65532:65532 data && chmod 700 data
install -m 0400 -o 65532 -g 65532 /path/to/oidc-secret secrets/oidc-secret
install -m 0400 -o 65532 -g 65532 /path/to/AuthKey_XXXX.p8 secrets/apns.p8
docker compose up -d && curl -s localhost:8740/healthz    # ok
```

Drop the two `apns` lines (flag and volume) to run without push wake-ups.

The reverse proxy terminates TLS and sends `/v1/*` and `/healthz` on `HUB_URL` to port 8740, and the management UI host
to port 8741. If the proxy runs in Docker on the same host, put both on a shared network instead of publishing ports.

**Updating:** pull the new commit, `make docker-hub` (or build on the host), `docker compose up -d`. The state
directory carries over.

**Back up** `data/`: it holds the rosters, adapter registrations and device tokens. Losing it means re-enrolling
phones and re-registering adapters; it holds nothing that can approve a request.

## The Warpgate adapter

The adapter's image is built on the Warpgate host from a binary you built and checked by sha256, and its guided
install (`install.sh`) writes the compose project to `/opt/interpose-adapter`. Steps:
[adapters/warpgate/README.md](../adapters/warpgate/README.md).

What the compose file ([`adapters/warpgate/deploy/compose.yaml`](../adapters/warpgate/deploy/compose.yaml)) enforces:
- its own user (65533), read-only root filesystem, all capabilities dropped, `no-new-privileges`;
- `mem_limit: 64m`, `pids_limit: 64`, `GOMEMLIMIT` in the image;
- only `./data` (key, hub token, trust list, open records, audit log) is writable;
- the Warpgate token mounted read-only as a secret file;
- no published ports: it only connects out, to the hub and to Warpgate.

## A new adapter

Follow the same pattern: a `deploy/` directory beside the adapter with a `Dockerfile` on `distroless/static`, a compose
file with the hardening above, and an `.env` template without real host names. Add its image build to the Docker job
in `.github/workflows/ci.yml`.
