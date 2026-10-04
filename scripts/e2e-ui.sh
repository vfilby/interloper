#!/bin/bash
# End to end with the real app in the iOS simulator: hub + demo adapter on loopback, XCUITest taps Approve.
# Needs: xcodegen, Xcode, an "iPhone 17 Pro" iOS 26.4 simulator (edit DEST for another).
# Run from anywhere; builds the Go commands into a temp dir. Uses loopback ports 8740 (hub API), 8741 (management UI)
# and 8749 (demo source), which must be free.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
S=$(mktemp -d -t wga-e2e)
B="$S/bin"
(cd "$ROOT/broker" && go build -o "$B/" ./cmd/...)
cd "$S"
echo "work dir: $S"
IOS="$ROOT/ios"
DEST=${DEST:-"platform=iOS Simulator,name=iPhone 17 Pro,OS=26.4"}
(cd "$IOS" && xcodegen generate -q && xcodebuild -project Approver.xcodeproj -scheme Approver -destination "$DEST" \
  -derivedDataPath build build-for-testing CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual -quiet)

"$B/wga-hub" -state hub-data -url http://127.0.0.1:8740 > hub.log 2>&1 &
HUB=$!
trap 'kill $HUB ${AD:-} ${XT:-} 2>/dev/null || true' EXIT
sleep 1
"$B/wga-adapter" key -dir ad > key.txt
PUB=$(awk '/public key/ {print $3}' key.txt)
curl -sf -X POST localhost:8741/adapters -H 'Sec-Fetch-Site: same-origin' --data-urlencode id=demo --data-urlencode "key=$PUB" \
  | grep -A1 'shown once' | tail -1 | sed -E 's/.*<code>([^<]+)<\/code>.*/\1/' > ad/hub-token
"$B/wga-adapter" run -id demo -source demo -dir ad -hub http://127.0.0.1:8740 -poll 500ms > adapter.log 2>&1 &
AD=$!
sleep 1
curl -sf localhost:8749/requests -d '{"requester":"claude","title":"claude wants RW on forge-01","risk":"elevated","reason":"fix the backups","facts":[{"label":"Host","value":"forge-01"},{"label":"Access","value":"RW","level":"warn"},{"label":"Duration","value":"2h"}]}' >/dev/null
curl -sf localhost:8749/requests -d '{"requester":"maggy","title":"maggy wants ADMIN on n","risk":"high","reason":"rotate certs ‮(bidi trick)","facts":[{"label":"Host","value":"n"},{"label":"Access","value":"ADMIN","level":"danger"}],"on_behalf_of":{"principal":"slack:U0123","display":"Kim","attested_by":"nanoclaw@drones"}}' >/dev/null

LINK=$(curl -sf -X POST localhost:8741/enroll -H 'Sec-Fetch-Site: same-origin' | grep -o 'wga://enroll[^<"]*' | head -1 | sed 's/&amp;/\&/g')
xcrun simctl uninstall booted co.filby.approver 2>/dev/null || true
xcrun simctl keychain booted reset  # the simulator keychain outlives an uninstall: start unenrolled

echo "== starting UI test"
( cd "$IOS" && TEST_RUNNER_WGA_ENROLL_LINK="$LINK" xcodebuild -project Approver.xcodeproj -scheme Approver \
    -destination "$DEST" -derivedDataPath build \
    -resultBundlePath "$S/ui.xcresult" test-without-building CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual > "$S/xcodebuild.log" 2>&1 ) &
XT=$!

echo "== waiting for the app to enroll, then trusting its card at the adapter (the admin step)"
for i in $(seq 1 120); do
  DEV=$(python3 -c 'import json; d=json.load(open("hub-data/state.json")).get("devices",{}); print(next(iter(d),""))' 2>/dev/null || true)
  [ -n "$DEV" ] && break
  sleep 1
done
[ -n "$DEV" ] || { echo "app never enrolled"; tail -30 xcodebuild.log; exit 1; }
curl -sf "localhost:8741/devices/$DEV/card.json" > card.json
"$B/wga-adapter" trust add -dir ad card.json

wait $XT && echo "UI TEST PASSED" || { echo "UI TEST FAILED"; grep -E "error|fail|XCT" xcodebuild.log | head -30; }
echo "== service-side outcome"
curl -sf localhost:8749/requests | python3 -c 'import json,sys; [print(e["item"]["title"], "->", e.get("outcome")) for e in json.load(sys.stdin)]'
echo "== adapter audit"
cut -c1-220 ad/audit.jsonl
grep -E "Test Case|Executed" xcodebuild.log | tail -4
