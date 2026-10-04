# Approver (iOS)

Native SwiftUI app: the device half of [docs/PROTOCOL.md](../docs/PROTOCOL.md). No third-party dependencies, no
React Native / Expo.

```
ios/
  project.yml        XcodeGen spec (Approver.xcodeproj is generated, not committed)
  Approver/          the app: enrollment, inbox, request detail, device settings
  ApproverKit/       Swift package with everything testable: wire types, base64url, fingerprints, envelope
                     verification, HPKE open, decision/card signing, key stores, hub client
```

## Build and test

```
cd ios/ApproverKit && swift test          # protocol + interop with the Go side (testdata/interop)
cd ios && xcodegen generate               # writes Approver.xcodeproj
xcodebuild -project Approver.xcodeproj -scheme Approver \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -derivedDataPath build \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual build
```

Sign to run locally (`CODE_SIGN_IDENTITY=-`) rather than `CODE_SIGNING_ALLOWED=NO`: an unsigned app builds, but at
run time every Keychain call fails with -34018 (missing entitlement), so it cannot enroll.

Or open `Approver.xcodeproj` in Xcode and run. A device build needs a signing team (set it in Xcode; it is not in
`project.yml`).

## Run against a local hub (simulator)

1. Start the hub with its device API on `http://127.0.0.1:8740` (the simulator shares the Mac's loopback).
2. In the management UI, create an enrollment code. Open the link in the simulator:
   `xcrun simctl openurl booted 'wga://enroll?hub=http%3A%2F%2F127.0.0.1%3A8740&code=<code>'`,
   or paste it into the Enroll screen.
3. Enroll. The summary shows the device fingerprint and the adapters it pinned. Compare them with the management UI
   and with what each adapter prints.
4. Tell each adapter to trust the device (`adapter trust add`), then requests show up in the inbox. The app polls
   every 5 s while in the foreground; pull to refresh.

The simulator always uses **software keys** (orange INSECURE banner): it reports a Secure Enclave, but its Face ID
and app-password access control are not the real thing. A device uses the Secure Enclave:

| Key | Access control |
|---|---|
| approve | `.privateKeyUsage` + `.biometryCurrentSet` **or** `.applicationPassword` (the app PIN set at enrollment), `WhenPasscodeSetThisDeviceOnly` |
| deny | `.privateKeyUsage`, `WhenUnlockedThisDeviceOnly` |
| encryption | `.privateKeyUsage`, `AfterFirstUnlockThisDeviceOnly` |

The Keychain holds each key's `dataRepresentation` (a handle only this Secure Enclave can use) and the hub token.
Adapter pins are public keys, kept in UserDefaults.

## End-to-end UI test

`scripts/e2e-ui.sh` (repository root) runs a real hub and the demo adapter on loopback. It then runs
`ApproverUITests` in the simulator:
1. The app enrolls from the link, through the `-wgaAutoEnroll` launch argument (simulator Debug builds only). The
   script does the admin step: it downloads the card from the management UI and runs `wga-adapter trust add`.
2. The test opens a normal-risk request, taps Approve, and waits for the adapter's verified ack.
3. It opens a high-risk request and checks that a tap does **not** approve it, then that a long press does.

The script checks the demo service's outcome afterwards. `scripts/e2e-cli.sh` is the same flow with the Go software
device instead of the app.

## What the app enforces

- A record is shown only if all of these hold:
  - the box is addressed to this device and opens;
  - the record is signed by the **pinned** key of the adapter the hub listed;
  - its inner `adapter` and `id` match both the signer and the hub's listing.

  Anything else goes to "Refused (not shown)".
- Adapter keys are pinned on first sight. A different key for a pinned adapter is shown as a conflict and never used.
- The detail view shows the adapter-written fields first: title, requester, on-behalf-of with who attested it, facts
  coloured by level, lease, expiry. The requester's reason comes after them, quoted and labelled as their claim.
  All requester and adapter text is sanitized: control and format (bidi, zero-width) characters are removed and it
  is shown on one line.
- `risk: high` needs a press-and-hold before the approve signature (and its Face ID prompt).
- Acks:
  - `approved`, `denied` and `expired` are final.
  - `rejected` and `failed` are notes: shown as a warning, with Approve/Deny still available. A new tap signs a fresh
    decision on the same record. A note counts only if its `decision_hash` is this device's latest decision.
  - An ack that does not verify shows as "unconfirmed".
  - `since` is the highest verified ack `ts` seen, minus 5 s.

## Not built yet (TODO)

- **APNs** and a **Notification Service Extension** to decrypt and verify pushes and show authoritative-first
  notifications, with a lock-screen Deny action (signed with the deny key).
- **App Attest** assertion at enrollment.
- **Off-network transport.** Only the direct path is implemented: the hub's HTTP API on LAN/VPN.
- An in-app **QR scanner**. The Camera app opening the `wga://` link covers enrollment for now.
- **Untested on hardware:** Secure Enclave key creation with `.applicationPassword` and the PIN path. The simulator
  only exercises software keys.
- Device-side revocation handling and key rotation; Apple Watch approve.
