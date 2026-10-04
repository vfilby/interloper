#!/bin/bash
# End to end with the software device: hub + demo adapter + wga-device, over loopback HTTP.
# Run from anywhere; builds the Go commands into a temp dir. Uses its own loopback ports 18740 (hub API), 18741 (management UI)
# and 18749 (demo source), so it never touches a hub you are running on the default ports; it stops if they are busy.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
S=$(mktemp -d -t wga-e2e)
B="$S/bin"
(cd "$ROOT/broker" && go build -o "$B/" ./cmd/...)
cd "$S"
echo "work dir: $S"
for p in 18740 18741 18749; do
  if lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1; then echo "port $p is in use (lsof -nP -iTCP:$p); not starting"; exit 1; fi
done

"$B/wga-hub" -state hub-data -api 127.0.0.1:18740 -admin 127.0.0.1:18741 -url http://127.0.0.1:18740 > hub.log 2>&1 &
HUB=$!
trap 'kill $HUB ${AD:-} 2>/dev/null || true' EXIT
sleep 1
curl -sf localhost:18740/healthz

echo "== adapter key"
"$B/wga-adapter" key -dir ad | tee key.txt
PUB=$(awk '/public key/ {print $3}' key.txt)

echo "== register adapter via the management UI form"
PAGE=$(curl -sf -X POST localhost:18741/adapters -H 'Sec-Fetch-Site: same-origin' --data-urlencode id=demo --data-urlencode "key=$PUB")
TOKEN=$(printf '%s' "$PAGE" | grep -A1 'shown once' | tail -1 | sed -E 's/.*<code>([^<]+)<\/code>.*/\1/')
[ -n "$TOKEN" ] || { echo "no token in page"; exit 1; }
printf '%s\n' "$TOKEN" > ad/hub-token; chmod 400 ad/hub-token

echo "== cross-site POST is refused"
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:18741/enroll -H 'Sec-Fetch-Site: cross-site'

newlink() { curl -sfL localhost:18741/enroll -H 'Sec-Fetch-Site: same-origin' --data-urlencode "user=$1" --data-urlencode "mode=$2" \
  | grep -o 'wga://enroll[^<"'"'"']*' | head -1 | sed 's/&amp;/\&/g'; }

echo "== new user vince: first software phone"
LINK=$(newlink vince new)
echo "link: ${LINK:0:60}…"
"$B/wga-device" init -f dev.json -name "phone one"
"$B/wga-device" enroll -f dev.json "$LINK" | tee enroll.txt
ACCOUNT=$(awk '/account fingerprint/ {print $3}' enroll.txt)
[ -n "$ACCOUNT" ] || { echo "no account fingerprint"; exit 1; }

echo "== the adapter trusts vince (once; later phones need nothing here)"
"$B/wga-adapter" trust add-user -dir ad vince "$ACCOUNT"

echo "== run adapter (demo source)"
"$B/wga-adapter" run -id demo -source demo -dir ad -hub http://127.0.0.1:18740 -poll 500ms -demo-listen 127.0.0.1:18749 > adapter.log 2>&1 &
AD=$!
sleep 1
curl -sf localhost:18749/requests -d '{"requester":"maggy","title":"maggy wants ADMIN on n","risk":"high","reason":"rotate certs ‮evil","facts":[{"label":"Host","value":"n"},{"label":"Access","value":"ADMIN","level":"danger"}],"on_behalf_of":{"principal":"slack:U0123","display":"Kim","attested_by":"nanoclaw@drones"}}' >/dev/null
curl -sf localhost:18749/requests -d '{"requester":"claude","title":"claude wants RW on forge-01","risk":"elevated","reason":"fix backups"}' >/dev/null
sleep 1.5

echo "== phone one lists, approves one, denies the other"
"$B/wga-device" list -f dev.json | tee list.txt
ID1=$(grep 'ADMIN on n' list.txt | awk '{print $1}')
ID2=$(grep 'RW on forge-01' list.txt | awk '{print $1}')
"$B/wga-device" approve -f dev.json "$ID1"
"$B/wga-device" deny -f dev.json "$ID2"

echo "== a second phone joins vince; phone one admits it"
"$B/wga-device" init -f dev2.json -name "phone two"
"$B/wga-device" enroll -f dev2.json "$(newlink vince join)"
"$B/wga-device" joins -f dev.json
DEV2=$("$B/wga-device" joins -f dev.json | awk 'NR==1 {print $1}')
"$B/wga-device" admit -f dev.json "$DEV2"
"$B/wga-device" roster -f dev2.json

echo "== phone two approves a request sealed to it"
curl -sf localhost:18749/requests -d '{"requester":"claude","title":"claude wants RW on build-02","risk":"elevated","reason":"after the join"}' >/dev/null
sleep 1.5
ID3=$("$B/wga-device" list -f dev2.json | grep 'build-02' | awk '{print $1}')
"$B/wga-device" approve -f dev2.json "$ID3"

echo "== phone one removes phone two; phone two is no longer served"
"$B/wga-device" remove -f dev.json "$DEV2"
("$B/wga-device" list -f dev2.json 2>&1 || true) | tail -1  # expected: refused

echo "== service-side outcome"
curl -sf localhost:18749/requests | python3 -c 'import json,sys; [print(e["item"]["key"], e["item"]["title"], "->", e.get("outcome")) for e in json.load(sys.stdin)]'
echo "== adapter audit"
cut -c1-200 ad/audit.jsonl
sleep 1  # one adapter poll, so it has seen the removal
echo "== adapter's view of vince"
"$B/wga-adapter" trust list -dir ad
