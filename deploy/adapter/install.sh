#!/bin/bash
# install.sh: install or update the Interloper Warpgate adapter in /opt/interloper-adapter on interloper.
# Runbook: docs/runbooks/deploy-clearing-house.md. Run it from the directory the deploy files were copied to:
#   cd ~/interloper-staging && sudo ./install.sh
#
# First install: warpgate-token (minted with `wg-apply --mint-token interloper-adapter`) must be here too. Every secret
# found here is moved into place and the copy shredded. .env (your settings) is created once and never overwritten.
# The adapter starts only when it has a hub token and trusts at least one account; until then this stops and says
# what is missing.
set -euo pipefail

DEST=/opt/interloper-adapter
CUID=65533 # the container's user (compose.yaml)
HERE=$(cd "$(dirname "$0")" && pwd)

step() { printf '\n== %s\n' "$*"; }
die() { printf '\nSTOPPED: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run it with sudo: cd $HERE && sudo ./install.sh"
for f in Dockerfile compose.yaml wga-adapter adapter.env.default; do
  [ -f "$HERE/$f" ] || die "$HERE/$f is missing. Copy all of deploy/adapter/ from the Mac after running make dist-adapter."
done

step "Check the adapter binary"
echo "sha256 here: $(sha256sum "$HERE/wga-adapter" | cut -d' ' -f1)"
read -r -p "Is that the same sha256 that 'make dist-adapter' printed on the Mac? [y/N] " answer
[ "$answer" = y ] || [ "$answer" = Y ] || die "binary not confirmed; nothing was changed"

step "Check the Warpgate token"
if [ -s "$HERE/warpgate-token" ]; then echo "warpgate-token: new copy found here, will be installed"
elif [ -s "$DEST/secrets/warpgate-token" ]; then echo "warpgate-token: keeping the installed one"
else die "no warpgate-token here or installed (wg-apply --mint-token interloper-adapter; runbook step 2)"; fi

step "Install files into $DEST"
install -d -m 0755 -o root -g root "$DEST"
install -d -m 0700 -o "$CUID" -g "$CUID" "$DEST/secrets" "$DEST/data"
install -m 0644 -o root -g root "$HERE/Dockerfile" "$HERE/compose.yaml" "$DEST/"
install -m 0755 -o root -g root "$HERE/wga-adapter" "$DEST/"
if [ -f "$DEST/.env" ]; then
  echo ".env: kept yours"
else
  install -m 0644 -o root -g root "$HERE/adapter.env.default" "$DEST/.env"
  echo ".env: created from the defaults"
fi
if grep -q 'home\.example' "$DEST/.env"; then
  die "$DEST/.env still has placeholder host names (home.example): set HUB_URL and WARPGATE_URL, then run this again"
fi
if [ -s "$HERE/warpgate-token" ]; then
  install -m 0400 -o "$CUID" -g "$CUID" "$HERE/warpgate-token" "$DEST/secrets/warpgate-token"
  shred -u "$HERE/warpgate-token"
  echo "warpgate-token: installed, copy here shredded"
fi

cd "$DEST"
step "Build the image"
docker compose build

step "The adapter's signing key (made once, kept in $DEST/data)"
docker compose run --rm --no-deps adapter-warpgate key -dir /data

if [ ! -s "$DEST/data/hub-token" ]; then
  die "no hub token yet. In the hub's management UI (Adapters), register id 'warpgate' with the public key above, then:
  printf '%s\n' '<token shown once>' | sudo install -m 0400 -o $CUID -g $CUID /dev/stdin $DEST/data/hub-token
and run this again."
fi
if ! docker compose run --rm --no-deps adapter-warpgate trust list -dir /data | grep -q 'account'; then
  die "the adapter trusts no account yet. With the fingerprint READ OFF A PHONE on the account (Device tab):
  cd $DEST && sudo docker compose run --rm --no-deps adapter-warpgate trust add-user -dir /data <user> <account fingerprint>
and run this again."
fi

step "Start the service"
docker compose up -d
docker compose ps

step "Done"
echo "Follow the log:   cd $DEST && sudo docker compose logs -f"
echo "Remove the copy:  rm -rf $HERE"
