#!/bin/bash
# install.sh: install or update the mail adapter in /opt/interpose-adapter-mailpit, on the Mailpit host.
# Runbook: adapters/mailpit/README.md. Run it from the directory the deploy files were copied to:
#   cd ~/adapter-mailpit-staging && sudo ./install.sh [--instance NAME] [sha256]
# --instance NAME: a second adapter for a second Mailpit on the same host, in /opt/interpose-adapter-mailpit-NAME (its
# own compose project, settings, login and keys). Give the same --instance again to update it.
# With the sha256 that `make dist-adapter-mailpit` printed, the binary is checked against it without asking. A binary
# already confirmed once is not asked about again.
#
# A guided install: it does everything it can, and where it needs you (a value from the hub's UI or the phone, a line
# in Mailpit's login file) it says what to do, waits, and checks. Run it again any time: finished steps are skipped, so
# it is also the update command. Only real problems stop it, marked ERROR.
set -euo pipefail

inst=''
if [ "${1:-}" = --instance ]; then
  inst=${2:-}
  [[ $inst =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || { echo "--instance NAME: lowercase letters, digits and -" >&2; exit 1; }
  shift 2
fi
DEST=/opt/interpose-adapter-mailpit${inst:+-$inst}
CUID=65534 # the container's user (compose.yaml)
HERE=$(cd "$(dirname "$0")" && pwd)
SVC=adapter-mailpit
BIN=interpose-adapter-mailpit
htok='' user='' afp='' # filled in by ask

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
# mailpit_status: the HTTP status of Mailpit's API for the adapter's login.
mailpit_status() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 10 -K - "$(envget MAILPIT_URL)/api/v1/info" <<<"user = \"$(envget MAILPIT_USER):$(cat "$DEST/secrets/mailpit-password")\""
}

RUN="sudo ./install.sh${inst:+ --instance $inst}"
[ "$(id -u)" = 0 ] || fail "run it with sudo: cd $HERE && $RUN"
[ -t 0 ] || fail "run it in an interactive terminal: it asks for values along the way"
for f in Dockerfile compose.yaml "$BIN" adapter.env.default; do
  [ -f "$HERE/$f" ] || fail "$HERE/$f is missing. Copy all of adapters/mailpit/deploy/ here after running make dist-adapter-mailpit."
done
command -v docker >/dev/null || fail "docker is not installed on this host"
command -v curl >/dev/null || fail "curl is needed to check the hub and Mailpit"
command -v openssl >/dev/null || fail "openssl is needed to make the Mailpit password"

step "1/8 The adapter binary"
sum=$(sha256sum "$HERE/$BIN" | cut -d' ' -f1)
want=$(printf '%s' "${1:-}" | tr 'A-F' 'a-f')
if [ -n "$want" ]; then
  [ "$sum" = "$want" ] || fail "the binary here has sha256 $sum, not the $want you gave: copy the binary you built"
  ok "binary matches the sha256 given ($sum)"
elif [ "$(cat "$DEST/.confirmed-sha256" 2>/dev/null)" = "$sum" ]; then
  ok "same binary as confirmed before ($sum)"
else
  echo "sha256: $sum"
  confirm "Is that the same sha256 that 'make dist-adapter-mailpit' printed where you built it?" ||
    fail "binary not confirmed; nothing was changed. Copy the binary you built, then run this again."
  ok "binary confirmed"
fi

step "2/8 Settings (.env)"
install -d -m 0755 -o root -g root "$DEST"
if [ ! -f "$DEST/.env" ]; then
  if [ -f "$HERE/.env" ]; then src="$HERE/.env"; else src="$HERE/adapter.env.default"; fi
  install -m 0644 -o root -g root "$src" "$DEST/.env"
  # A new instance from the defaults gets its own adapter id; MAILPIT_URL and MAILPIT_USER still need checking.
  if [ -n "$inst" ] && [ "$src" = "$HERE/adapter.env.default" ]; then sed -i "s/^ADAPTER_ID=.*/ADAPTER_ID=mail-$inst/" "$DEST/.env"; fi
fi
hub=$(envget HUB_URL)
if [[ $hub == *home.example* || -z $hub ]]; then
  yourturn "the hub's address" "The hub's public URL (the one phones use), e.g. https://hub.example.org"
  ask hub "Hub URL: " '^https://[A-Za-z0-9.-]+(:[0-9]+)?/?$'
  sed -i "s#^HUB_URL=.*#HUB_URL=${hub%/}#" "$DEST/.env"
fi
hub=$(envget HUB_URL); id=$(envget ADAPTER_ID); id=${id:-mail}
ok "settings in $DEST/.env (hub $hub, Mailpit $(envget MAILPIT_URL) as $(envget MAILPIT_USER), adapter id $id)"
[ "$(curl -fsS --max-time 10 "$hub/healthz" 2>/dev/null)" = ok ] || fail "the hub at $hub does not answer /healthz with ok (check HUB_URL in $DEST/.env, DNS, the proxy)"
ok "hub reachable"

step "3/8 The adapter's Mailpit login"
install -d -m 0700 -o "$CUID" -g "$CUID" "$DEST/secrets" "$DEST/data"
if [ ! -s "$DEST/secrets/mailpit-password" ]; then
  openssl rand -base64 30 | tr -d '/+=\n' | install -m 0400 -o "$CUID" -g "$CUID" /dev/stdin "$DEST/secrets/mailpit-password"
  ok "made a new password"
fi
code=$(mailpit_status)
if [ "$code" != 200 ]; then
  line="$(envget MAILPIT_USER):$(openssl passwd -apr1 "$(cat "$DEST/secrets/mailpit-password")")"
  yourturn "give the adapter a Mailpit login (Mailpit answered HTTP $code)" \
    "1. Add this line to the ui-users file of the Mailpit this adapter guards (its MP_UI_AUTH_FILE):" \
    "     $line" \
    "2. Recreate that Mailpit container so it reads the file again (docker compose up -d --force-recreate ...)." \
    "Press Enter when done."
  read -r _
  code=$(mailpit_status)
  [ "$code" = 200 ] || fail "Mailpit still answers HTTP $code for $(envget MAILPIT_USER); check the line and MAILPIT_URL, then run this again"
fi
ok "Mailpit accepts the adapter's login"

step "4/8 Install the files and build the image"
install -m 0644 -o root -g root "$HERE/Dockerfile" "$HERE/compose.yaml" "$DEST/"
install -m 0755 -o root -g root "$HERE/$BIN" "$DEST/"
printf '%s\n' "$sum" > "$DEST/.confirmed-sha256"
compose build --quiet
ok "image built"

step "5/8 Register the adapter at the hub"
keyout=$(compose run --rm --no-deps "$SVC" key -dir /data)
pub=$(printf '%s\n' "$keyout" | sed -n 's/^public key: *//p')
fp=$(printf '%s\n' "$keyout" | sed -n 's/^fingerprint: *//p')
[ -n "$pub" ] || fail "could not read the adapter's public key: $keyout"
if [ -s "$DEST/data/hub-token" ]; then
  ok "already registered (hub token installed); adapter fingerprint $fp"
else
  yourturn "register at the hub" \
    "1. Open $hub and sign in as an admin." \
    "2. Adapters: id  $id" \
    "             key $pub" \
    "   (this is the PUBLIC key; the private one never leaves $DEST/data)" \
    "3. Register. The page shows a token once: copy it and paste it below (it is not shown)."
  ask htok "Hub token for $id: " '^.{16,}$' hidden
  printf '%s\n' "$htok" | install -m 0400 -o "$CUID" -g "$CUID" /dev/stdin "$DEST/data/hub-token"
  unset htok
  ok "hub token installed"
fi

step "6/8 Trust an account"
trusted=$(compose run --rm --no-deps "$SVC" trust list -dir /data | grep ' account ' || true)
if [ -n "$trusted" ]; then
  printf '%s\n' "$trusted"
  ok "trusting the account(s) above"
  if confirm "Trust another account as well?"; then trusted=""; fi
fi
if [ -z "$trusted" ]; then
  yourturn "trust your account" \
    "On a phone that is on the account: Interpose → Device tab → the Account section (not the Device section)." \
    "Enter the user id (next to Account) and the Account fingerprint: 8 groups of 4, xxxx-xxxx-...-xxxx." \
    "(The 4-group fingerprint at the top of the tab is the device's, not the account's.)" \
    "Read them off the phone, never off the hub's page: a lying hub would get its own account trusted."
  ask user "User id:             " '^[a-z0-9._-]{1,40}$'
  ask afp  "Account fingerprint: " '^[0-9a-f]{4}(-[0-9a-f]{4}){7}$'
  compose run --rm --no-deps "$SVC" trust add-user -dir /data "$user" "$afp"
  ok "trusting $user"
fi

step "7/8 Start"
compose up -d
for _ in $(seq 1 15); do
  sleep 1
  if compose logs "$SVC" 2>/dev/null | grep -q '"msg":"started"'; then break; fi
done
compose logs "$SVC" 2>/dev/null | grep -q '"msg":"started"' ||
  fail "the adapter did not report \"started\"; see: cd $DEST && sudo docker compose logs $SVC"
ok "the adapter is running"

step "8/8 Check"
yourturn "check on the phone" \
  "Interpose → Device → Check hub for new adapters." \
  "The adapter '$id' must show fingerprint  $fp" \
  "Then send a message to an address the gate does not auto-send to: the phone should get it within seconds."
printf '\nLogs:      cd %s && sudo docker compose logs -f\n' "$DEST"
printf 'Clean up:  rm -rf %s\n' "$HERE"
