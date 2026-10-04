#!/bin/bash
# End to end with the real app in the iOS simulator: hub + demo adapter on loopback, XCUITest taps Approve.
# Needs: xcodegen, Xcode, an "iPhone 17 Pro" iOS 26.4 simulator (edit DEST for another).
# Run from anywhere; builds the Go commands into a temp dir. Uses its own loopback ports 18740 (hub API), 18741 (management UI)
# and 18749 (demo source), so it never touches a hub you are running on the default ports; it stops if they are busy.
# It UNINSTALLS the Approver app from the booted simulator and resets the simulator keychain: any enrollment you made
# there by hand is lost.
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
IOS="$ROOT/ios"
DEST=${DEST:-"platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4"}
(cd "$IOS" && xcodegen generate -q && xcodebuild -project Approver.xcodeproj -scheme Approver -destination "$DEST" \
  -derivedDataPath build build-for-testing CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual -quiet)

"$B/wga-hub" -state hub-data -api 127.0.0.1:18740 -admin 127.0.0.1:18741 -url http://127.0.0.1:18740 > hub.log 2>&1 &
HUB=$!
trap 'kill $HUB ${AD:-} ${XT:-} 2>/dev/null || true' EXIT
sleep 1
curl -sf localhost:18740/healthz >/dev/null || { echo "test hub did not start:"; cat hub.log; exit 1; }
"$B/wga-adapter" key -dir ad > key.txt
PUB=$(awk '/public key/ {print $3}' key.txt)
curl -sf -X POST localhost:18741/adapters -H 'Sec-Fetch-Site: same-origin' --data-urlencode id=demo --data-urlencode "key=$PUB" \
  | grep -A1 'shown once' | tail -1 | sed -E 's/.*<code>([^<]+)<\/code>.*/\1/' > ad/hub-token
"$B/wga-adapter" run -id demo -source demo -dir ad -hub http://127.0.0.1:18740 -poll 500ms -demo-listen 127.0.0.1:18749 > adapter.log 2>&1 &
AD=$!
sleep 1
curl -sf localhost:18749/requests -d '{"requester":"claude","title":"claude wants RW on forge-01","risk":"elevated","reason":"fix the backups","facts":[{"label":"Host","value":"forge-01"},{"label":"Access","value":"RW","level":"warn"},{"label":"Duration","value":"2h"}]}' >/dev/null
curl -sf localhost:18749/requests -d '{"requester":"maggy","title":"maggy wants ADMIN on n","risk":"high","reason":"rotate certs ‮(bidi trick)","facts":[{"label":"Host","value":"n"},{"label":"Access","value":"ADMIN","level":"danger"}],"on_behalf_of":{"principal":"slack:U0123","display":"Kim","attested_by":"nanoclaw@drones"}}' >/dev/null

newlink() { curl -sfL localhost:18741/enroll -H 'Sec-Fetch-Site: same-origin' --data-urlencode "user=$1" --data-urlencode "mode=$2" \
  | grep -o 'wga://enroll[^<"'"'"']*' | head -1 | sed 's/&amp;/\&/g'; }
# The simulator becomes vince's first phone through phone sign-in (local mode: /app/enroll?user=vince); the test asks
# the management UI for a join code itself later.
xcrun simctl uninstall booted com.eff3.interloper 2>/dev/null || true
xcrun simctl keychain booted reset  # the simulator keychain outlives an uninstall: start unenrolled

echo "== starting UI test"
( cd "$IOS" && TEST_RUNNER_WGA_ADMIN_URL="http://127.0.0.1:18741" xcodebuild -project Approver.xcodeproj -scheme Approver \
    -destination "$DEST" -derivedDataPath build \
    -resultBundlePath "$S/ui.xcresult" test-without-building CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual > "$S/xcodebuild.log" 2>&1 ) &
XT=$!

echo "== waiting for the app to create user vince, then trusting vince at the adapter (the admin step)"
account() { python3 -c '
import base64, hashlib, json
u = json.load(open("hub-data/state.json")).get("users", {}).get("vince")
p = u["chain"][0]["payload"]; p += "=" * (-len(p) % 4)
h = hashlib.sha256(base64.urlsafe_b64decode(p)).hexdigest()[:32]
print("-".join(h[i:i+4] for i in range(0, 32, 4)))' 2>/dev/null || true; }
for i in $(seq 1 120); do
  ACCOUNT=$(account)
  [ -n "$ACCOUNT" ] && break
  sleep 1
done
[ -n "$ACCOUNT" ] || { echo "app never enrolled"; tail -30 xcodebuild.log; exit 1; }
"$B/wga-adapter" trust add-user -dir ad vince "$ACCOUNT"

wait $XT && echo "UI TEST PASSED" || { echo "UI TEST FAILED"; grep -E "error|fail|XCT" xcodebuild.log | head -30; }
echo "== service-side outcome"
curl -sf localhost:18749/requests | python3 -c 'import json,sys; [print(e["item"]["title"], "->", e.get("outcome")) for e in json.load(sys.stdin)]'
echo "== adapter audit"
cut -c1-220 ad/audit.jsonl
grep -E "Test Case|Executed" xcodebuild.log | tail -4
