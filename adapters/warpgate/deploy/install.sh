#!/bin/bash
# install.sh: install or update the Warpgate adapter in /opt/interpose-adapter, on the Warpgate host.
# Runbook: adapters/warpgate/README.md. Run it from the directory the deploy files were copied to:
#   cd ~/adapter-staging && sudo ./install.sh [sha256]
# With the sha256 that `make dist-adapter` printed, the binary is checked against it without asking. A binary already
# confirmed once is not asked about again.
#
# A guided install: it does everything it can, and where it needs you (a value from the hub's UI or the phone) it
# says what to do, waits, and checks what you enter. Run it again any time: finished steps are skipped, so it is also
# the update command. Only real problems stop it, marked ERROR.
set -euo pipefail

DEST=/opt/interpose-adapter
CUID=65533 # the container's user (compose.yaml)
HERE=$(cd "$(dirname "$0")" && pwd)
SVC=adapter-warpgate
tok='' htok='' user='' afp='' reqs='' # filled in by ask

if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else B='' G='' Y='' R='' N=''; fi
step() { printf '\n%s== %s%s\n' "$B" "$*" "$N"; }
ok() { printf '%s✓%s %s\n' "$G" "$N" "$*"; }
fail() { printf '\n%sERROR:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
# yourturn TITLE LINES...: a box saying what the person has to do now.
yourturn() {
  local title=$1; shift
  printf '\n%s┌─ YOUR TURN: %s%s\n' "$Y" "$title" "$N"
  for l in "$@"; do printf '%s│%s %s\n' "$Y" "$N" "$l"; done
  printf '%s└─%s\n' "$Y" "$N"
}
# ask VAR PROMPT REGEX [hidden]: read a value until it matches REGEX (empty input asks again).
ask() {
  local __var=$1 prompt=$2 re=$3 hidden=${4:-} v
  while true; do
    if [ -n "$hidden" ]; then read -r -s -p "$prompt" v; echo; else read -r -p "$prompt" v; fi
    v=$(printf '%s' "$v" | tr -d '[:space:]')
    [[ $v =~ $re ]] && break
    printf '%sThat does not look right, try again.%s\n' "$Y" "$N"
  done
  printf -v "$__var" '%s' "$v"
}
confirm() { local a; read -r -p "$1 [y/N] " a; [ "$a" = y ] || [ "$a" = Y ]; }
compose() { (cd "$DEST" && docker compose "$@"); }
envget() { sed -n "s/^$1=//p" "$DEST/.env" 2>/dev/null | tail -1; }

[ "$(id -u)" = 0 ] || fail "run it with sudo: cd $HERE && sudo ./install.sh"
[ -t 0 ] || fail "run it in an interactive terminal: it asks for values along the way"
for f in Dockerfile compose.yaml wga-adapter adapter.env.default; do
  [ -f "$HERE/$f" ] || fail "$HERE/$f is missing. Copy all of adapters/warpgate/deploy/ here after running make dist-adapter."
done
command -v docker >/dev/null || fail "docker is not installed on this host"

step "1/7 The adapter binary"
sum=$(sha256sum "$HERE/wga-adapter" | cut -d' ' -f1)
want=$(printf '%s' "${1:-}" | tr 'A-F' 'a-f')
if [ -n "$want" ]; then
  [ "$sum" = "$want" ] || fail "the binary here has sha256 $sum, not the $want you gave: copy the binary you built"
  ok "binary matches the sha256 given ($sum)"
elif [ "$(cat "$DEST/.confirmed-sha256" 2>/dev/null)" = "$sum" ]; then
  ok "same binary as confirmed before ($sum)"
else
  echo "sha256: $sum"
  confirm "Is that the same sha256 that 'make dist-adapter' printed where you built it?" ||
    fail "binary not confirmed; nothing was changed. Copy the binary you built, then run this again."
  ok "binary confirmed"
fi

step "2/7 Settings (.env)"
install -d -m 0755 -o root -g root "$DEST"
if [ ! -f "$DEST/.env" ]; then
  if [ -f "$HERE/.env" ]; then src="$HERE/.env"; else src="$HERE/adapter.env.default"; fi
  install -m 0644 -o root -g root "$src" "$DEST/.env"
fi
hub=$(envget HUB_URL); wg=$(envget WARPGATE_URL)
if [[ $hub == *home.example* || -z $hub || $wg == *home.example* || -z $wg ]]; then
  yourturn "two addresses" \
    "The hub's public URL (the one phones use), e.g. https://hub.example.org" \
    "Warpgate's URL on this host, e.g. https://warpgate.example.org"
  ask hub "Hub URL:      " '^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$'
  ask wg  "Warpgate URL: " '^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$'
  sed -i -e "s#^HUB_URL=.*#HUB_URL=${hub%/}#" -e "s#^WARPGATE_URL=.*#WARPGATE_URL=${wg%/}#" "$DEST/.env"
fi
if [ -z "$(envget ALLOWED_REQUESTERS)" ]; then
  yourturn "who may ask" \
    "The Warpgate usernames whose ticket requests go to the phone, comma-separated (e.g. claude,helper)." \
    "Anyone else's requests are denied by the adapter's policy."
  ask reqs "Allowed requesters: " '^[A-Za-z0-9._-]+(,[A-Za-z0-9._-]+)*$'
  sed -i "s#^ALLOWED_REQUESTERS=.*#ALLOWED_REQUESTERS=$reqs#" "$DEST/.env"
fi
hub=$(envget HUB_URL); wg=$(envget WARPGATE_URL)
ok "settings in $DEST/.env (hub $hub, Warpgate $wg)"
if command -v curl >/dev/null; then
  [ "$(curl -fsS --max-time 10 "$hub/healthz" 2>/dev/null)" = ok ] || fail "the hub at $hub does not answer /healthz with ok (check HUB_URL in $DEST/.env, DNS, the proxy)"
  ok "hub reachable"
  curl -fsS -o /dev/null --max-time 10 "$wg/@warpgate/api/info" || fail "Warpgate at $wg does not answer (check WARPGATE_URL in $DEST/.env)"
  ok "Warpgate reachable"
fi

step "3/7 The Warpgate approver token"
install -d -m 0700 -o "$CUID" -g "$CUID" "$DEST/secrets" "$DEST/data"
if [ -s "$HERE/warpgate-token" ]; then
  install -m 0400 -o "$CUID" -g "$CUID" "$HERE/warpgate-token" "$DEST/secrets/warpgate-token"
  shred -u "$HERE/warpgate-token"
  ok "installed the token found here (the copy here is shredded)"
elif [ -s "$DEST/secrets/warpgate-token" ]; then
  ok "keeping the installed token"
else
  yourturn "Warpgate token" \
    "The adapter's own Warpgate approver token (approve/deny ticket requests only; see the runbook)." \
    "Paste it below; it is not shown."
  ask tok "Warpgate token: " '^.{16,}$' hidden
  printf '%s\n' "$tok" | install -m 0400 -o "$CUID" -g "$CUID" /dev/stdin "$DEST/secrets/warpgate-token"
  unset tok
  ok "token installed"
fi

step "4/7 Install the files and build the image"
install -m 0644 -o root -g root "$HERE/Dockerfile" "$HERE/compose.yaml" "$DEST/"
install -m 0755 -o root -g root "$HERE/wga-adapter" "$DEST/"
printf '%s\n' "$sum" > "$DEST/.confirmed-sha256"
compose build --quiet
ok "image built"

step "5/7 Register the adapter at the hub"
keyout=$(compose run --rm --no-deps "$SVC" key -dir /data)
pub=$(printf '%s\n' "$keyout" | sed -n 's/^public key: *//p')
fp=$(printf '%s\n' "$keyout" | sed -n 's/^fingerprint: *//p')
[ -n "$pub" ] || fail "could not read the adapter's public key: $keyout"
if [ -s "$DEST/data/hub-token" ]; then
  ok "already registered (hub token installed); adapter fingerprint $fp"
else
  yourturn "register at the hub" \
    "1. Open $hub and sign in as an admin." \
    "2. Adapters: id  warpgate" \
    "             key $pub" \
    "   (this is the PUBLIC key; the private one never leaves $DEST/data)" \
    "3. Register. The page shows a token once: copy it and paste it below (it is not shown)."
  ask htok "Hub token for warpgate: " '^.{16,}$' hidden
  printf '%s\n' "$htok" | install -m 0400 -o "$CUID" -g "$CUID" /dev/stdin "$DEST/data/hub-token"
  unset htok
  ok "hub token installed"
fi

step "6/7 Trust an account"
trusted=$(compose run --rm --no-deps "$SVC" trust list -dir /data | grep ' account ' || true)
if [ -n "$trusted" ]; then
  printf '%s\n' "$trusted"
  ok "trusting the account(s) above"
  if confirm "Trust another account as well?"; then trusted=""; fi
fi
if [ -z "$trusted" ]; then
  yourturn "trust your account" \
    "On a phone that is on the account: Interloper → Device tab → the Account section (not the Device section)." \
    "Enter the user id (next to Account) and the Account fingerprint: 8 groups of 4, xxxx-xxxx-...-xxxx." \
    "(The 4-group fingerprint at the top of the tab is the device's, not the account's.)" \
    "Read them off the phone, never off the hub's page: a lying hub would get its own account trusted."
  ask user "User id:             " '^[a-z0-9._-]{1,40}$'
  ask afp  "Account fingerprint: " '^[0-9a-f]{4}(-[0-9a-f]{4}){7}$'
  compose run --rm --no-deps "$SVC" trust add-user -dir /data "$user" "$afp"
  ok "trusting $user"
fi

step "7/7 Start"
compose up -d
for _ in $(seq 1 15); do
  sleep 1
  if compose logs "$SVC" 2>/dev/null | grep -q '"msg":"started"'; then break; fi
done
compose logs "$SVC" 2>/dev/null | grep -q '"msg":"started"' ||
  fail "the adapter did not report \"started\"; see: cd $DEST && sudo docker compose logs $SVC"
ok "the adapter is running"

yourturn "check on the phone" \
  "Interloper → Device → Check hub for new adapters." \
  "The adapter 'warpgate' must show fingerprint  $fp" \
  "Then file a Warpgate ticket request: the phone should get it within seconds."
printf '\nLogs:      cd %s && sudo docker compose logs -f\n' "$DEST"
printf 'Clean up:  rm -rf %s\n' "$HERE"
