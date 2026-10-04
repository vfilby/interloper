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
curl -sf localhost:18749/requests -d '{"requester":"claude","title":"claude wants RW on build-01","risk":"elevated","reason":"fix the backups","facts":[{"label":"Host","value":"build-01"},{"label":"Access","value":"RW","level":"warn"},{"label":"Duration","value":"2h"}]}' >/dev/null
curl -sf localhost:18749/requests -d '{"requester":"helper","title":"helper wants ADMIN on n","risk":"high","reason":"rotate certs ‮(bidi trick)","facts":[{"label":"Host","value":"n"},{"label":"Access","value":"ADMIN","level":"danger"}],"on_behalf_of":{"principal":"slack:U0123","display":"Kim","attested_by":"agent@agent-host"}}' >/dev/null

newlink() { curl -sf -X POST localhost:18741/enroll -H 'Sec-Fetch-Site: same-origin' | grep -o 'wga://enroll[^<"'"'"']*' | head -1 | sed 's/&amp;/\&/g'; }
LINK=$(newlink)
LINK2=$(newlink)  # for re-enrolling from the Device tab
xcrun simctl uninstall booted com.example.approver 2>/dev/null || true
xcrun simctl keychain booted reset  # the simulator keychain outlives an uninstall: start unenrolled

echo "== starting UI test"
( cd "$IOS" && TEST_RUNNER_WGA_ENROLL_LINK="$LINK" TEST_RUNNER_WGA_ENROLL_LINK2="$LINK2" xcodebuild -project Approver.xcodeproj -scheme Approver \
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
curl -sf "localhost:18741/devices/$DEV/card.json" > card.json
"$B/wga-adapter" trust add -dir ad card.json

wait $XT && echo "UI TEST PASSED" || { echo "UI TEST FAILED"; grep -E "error|fail|XCT" xcodebuild.log | head -30; }
echo "== service-side outcome"
curl -sf localhost:18749/requests | python3 -c 'import json,sys; [print(e["item"]["title"], "->", e.get("outcome")) for e in json.load(sys.stdin)]'
echo "== adapter audit"
cut -c1-220 ad/audit.jsonl
grep -E "Test Case|Executed" xcodebuild.log | tail -4
