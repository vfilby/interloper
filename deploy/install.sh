#!/bin/bash
# install.sh: install or update warpgate-approver in /opt/warpgate-approver on interloper.
#
# Run it from the directory the deploy files were copied to, on interloper:
#   cd ~/wga-staging && sudo ./install.sh
#
# First install: the three secret files (warpgate-token, pushover-token, pushover-user) must be in that directory too.
# Update: leave them out; the installed ones are kept. Every secret found here is moved into place and the copy here is
# shredded. broker.env (your settings) is created on the first install only and never overwritten.
set -euo pipefail

DEST=/opt/warpgate-approver
CUID=65532 # the container's user (distroless nonroot)
HERE=$(cd "$(dirname "$0")" && pwd)
SECRETS="warpgate-token pushover-token pushover-user"

step() { printf '\n== %s\n' "$*"; }
die() { printf '\nSTOPPED: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run it with sudo: cd $HERE && sudo ./install.sh"
for f in Dockerfile compose.yaml broker broker.env.default; do
  [ -f "$HERE/$f" ] || die "$HERE/$f is missing. Copy all of deploy/ from the Mac after running make dist."
done

step "Check the broker binary"
echo "sha256 here: $(sha256sum "$HERE/broker" | cut -d' ' -f1)"
read -r -p "Is that the same sha256 that 'make dist' printed on the Mac? [y/N] " answer
[ "$answer" = y ] || [ "$answer" = Y ] || die "binary not confirmed; nothing was changed"

step "Check the secrets"
missing=""
for s in $SECRETS; do
  if [ -s "$HERE/$s" ]; then echo "$s: new copy found here, will be installed"
  elif [ -s "$DEST/secrets/$s" ]; then echo "$s: keeping the installed one"
  else missing="$missing $s"; fi
done
[ -z "$missing" ] || die "missing secret(s):$missing. Copy them into $HERE first (runbook step 3); nothing was changed"

step "Install files into $DEST"
install -d -m 0755 -o root -g root "$DEST"
install -d -m 0700 -o "$CUID" -g "$CUID" "$DEST/secrets" "$DEST/data"
install -m 0644 -o root -g root "$HERE/Dockerfile" "$HERE/compose.yaml" "$DEST/"
install -m 0755 -o root -g root "$HERE/broker" "$DEST/"
if [ -f "$DEST/broker.env" ]; then
  echo "broker.env: kept yours ($(grep '^POLICY_MODE=' "$DEST/broker.env" || echo 'POLICY_MODE not set'))"
else
  install -m 0644 -o root -g root "$HERE/broker.env.default" "$DEST/broker.env"
  echo "broker.env: created from the defaults (POLICY_MODE=report)"
fi
for s in $SECRETS; do
  if [ -s "$HERE/$s" ]; then
    install -m 0400 -o "$CUID" -g "$CUID" "$HERE/$s" "$DEST/secrets/$s"
    shred -u "$HERE/$s"
    echo "$s: installed, copy in $HERE shredded"
  fi
done

cd "$DEST"
step "Build the image"
docker compose build

step "Check the configuration"
docker compose run --rm broker -check-config

step "Poll Warpgate once (a real poll; pending requests, if any, are notified)"
docker compose run --rm broker -once || die "the test poll failed (see the log lines above); the service was NOT started"

step "Start the service"
docker compose up -d
docker compose ps

step "Done"
echo "Follow the log:   cd $DEST && sudo docker compose logs -f"
echo "Remove the copy:  rm -rf $HERE"
