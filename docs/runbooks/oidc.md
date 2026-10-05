# Hub sign-in with Authelia (OIDC)

The hub's management UI, and phone sign-in in the app, authenticate with OIDC against Authelia
(`https://sso.home.example`, 4.39). This page is everything needed on both sides. **Nothing here has been applied to n
yet.**

What sign-in decides, and what it does not:
- **It decides** who may hand out enrollment codes and see what.
  - Members of `interpose_admins` see everything, register adapters and read the audit log.
  - Everyone else sees only their own account: they can create it (their first phone), add phones to it, and revoke
    their own phones at the hub.
- **It does not decide** which phones can approve. That is each user's roster, signed by their own phones
  (`docs/PROTOCOL.md`).
- **So a compromised Authelia account can start an enrollment, and nothing more.** The new phone still waits for
  approval on one of the user's existing phones, and adapters trust users by account fingerprint, not by what the hub
  or Authelia says.

## 1. LLDAP groups

Create, then add people to them:
- `interpose_users`: may sign in to the hub;
- `interpose_admins`: may sign in and is a hub admin.

## 2. Authelia (`DockerStacks/reverse-proxy/config/authelia/configuration.yml`)

Under `identity_providers.oidc.authorization_policies`:

```yaml
      interpose:
        default_policy: deny
        rules:
          - policy: two_factor
            subject:
              - 'group:interpose_users'
              - 'group:interpose_admins'
```

Under `identity_providers.oidc.claims_policies`. This puts the username and groups in the ID token, which Authelia
4.39 otherwise leaves out. The hub falls back to the userinfo endpoint if this is missing, but one round trip fewer is
better:

```yaml
    claims_policies:
      interpose:
        id_token: ['preferred_username', 'groups', 'name']
```

Under `identity_providers.oidc.clients`, modelled on the Mealie client:

```yaml
      - client_id: interpose
        client_name: Interpose Hub
        client_secret: '{{ env "AUTHELIA_OIDC_CLIENT_SECRET_INTERPOSE" }}'
        consent_mode: implicit
        require_pkce: true
        pkce_challenge_method: S256
        token_endpoint_auth_method: client_secret_basic
        claims_policy: interpose
        redirect_uris:
          - https://interpose-hub.home.example/oidc/callback
        scopes: ['openid', 'profile', 'email', 'groups']
        authorization_policy: interpose
```

Put the secret in the reverse-proxy `.env` as `AUTHELIA_OIDC_CLIENT_SECRET_INTERPOSE`, in the same form as the
other clients' secrets, and pass it through in `reverse-proxy/compose.yaml` like the others. Restart Authelia.

## 3. The hub

The management UI needs a stable https name: `interpose-hub.home.example` is assumed above, routed by Traefik to the hub's
`-admin` listener. Do **not** put Authelia forward-auth in front of it as well: the hub signs people in itself, and
`/oidc/callback` must reach it.

```
wga-hub \
  -api :8740 -url https://<hub API name>:8740 \
  -admin 0.0.0.0:8741 \
  -oidc-issuer https://sso.home.example \
  -oidc-client-id interloper \
  -oidc-secret-file /run/secrets/oidc-client-secret \
  -oidc-redirect https://interpose-hub.home.example/oidc/callback \
  -oidc-admin-group interpose_admins
```

- **Session cookies** are signed with `<state>/session.key`, made on first start. Delete it to sign everyone out.
- **Sessions** last 12 hours.
- **Without `-oidc-issuer`** the hub has no sign-in and refuses to start unless `-admin` is a loopback address
  (development only).

## 4. Phones

- In the app's Enroll screen, under **Sign in**, enter `https://interpose-hub.home.example`, then tap *Sign in to get a
  code*. Authelia (two-factor) opens in a private browser session.
- The hub sends the app back a code for you: a **new account** the first time, otherwise **another device**. Approve
  that device on one of your existing phones.
- Nothing is remembered between sign-ins.
- An admin can still hand out codes from the management UI (QR code, link, simulator command).

## Usernames

The hub user id is `preferred_username`, lower-cased, and must be 1–40 of `a-z 0-9 . _ -`. A username outside that
is refused at sign-in with a message saying why.
