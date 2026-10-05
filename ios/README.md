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
cd ios/ApproverKit && swift test          # protocol + interop with the Go side (internal/protocol/testdata/interop)
cd ios && xcodegen generate               # writes Approver.xcodeproj
xcodebuild -project Approver.xcodeproj -scheme Approver \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' -derivedDataPath build \
  CODE_SIGN_IDENTITY=- CODE_SIGN_STYLE=Manual build
```

Sign to run locally (`CODE_SIGN_IDENTITY=-`) rather than `CODE_SIGNING_ALLOWED=NO`: an unsigned app builds, but at
run time every Keychain call fails with -34018 (missing entitlement), so it cannot enroll.

Or open `Approver.xcodeproj` in Xcode and run. A device build needs a signing team (set it in Xcode; it is not in
`project.yml`).

## Connecting a device

The app opens on **Connect to Interloper**. There are three steps:

1. **Interloper server:** enter the address of your server, the page you manage it from (for example
   `interpose-hub.home.example`). The app checks it really is one (`/app/hello`) before going on.
2. **Continue on the server:** the app opens the server in a private browser session. You sign in there
   (Authelia, two-factor), and the server registers the device for you. The first time that is a new account;
   otherwise the device joins your account and waits for approval on a phone you already have.
3. **Connect this device:** name it, set the app PIN on a device with a Secure Enclave, and connect. The summary
   shows the device and account fingerprints.

The other way in is **I have an enrollment link or QR code**, using a code from the management page. Scanning its QR
code with the Camera app opens the app straight at step 3.

In the simulator against a local hub (no OIDC):
- The hub says it has no sign-in, so step 2 asks for a user id instead.
- Use `http://127.0.0.1:8741` as the server (the simulator shares the Mac's loopback).
- Or run the `xcrun simctl openurl booted '…'` command the management page shows, then click Open.

Then tell each adapter to trust the account (`interpose-adapter trust add-user vince <account fingerprint>`), and
requests show up in the inbox.

## Accounts (rosters)

A user's devices are the head of a signed roster chain (docs/PROTOCOL.md, "Users and rosters"). Adapters trust the
account, not single devices.

- **First device** (`mode=new`): creates the account's first roster, signed by itself, and pins the account fingerprint.
- **Another device** (`mode=join`): asks to join and is *pending*. The inbox shows its fingerprint until it is approved.
  It can decide nothing meanwhile.
- **Approving a join** (inbox, "Devices asking to join"):
  - compare the fingerprint with the new phone's screen, then Approve (Face ID);
  - this phone builds the next roster from its own verified copy of the chain, adds the card, signs it, and posts it.
- **Removing a device** (Device tab → Devices on this account): signs a roster without it. The last device cannot be
  removed. A removed device shows that it was removed and hides Approve/Deny.
- **Checks on every refresh:** the chain verifies back to the pinned account fingerprint, and it must **build on the
  head already accepted**:
  - never shorter;
  - holding exactly that roster at its seq.

  That stops rollbacks, and forks signed by a device after it was removed (it keeps its key). The accepted head's
  seq and payload hash are persisted. A refused chain shows a red error and the last good head stays.
- **Pinning on join:** a joining device pins the account fingerprint on the first verified chain that includes it.
  Before that, the fingerprint is shown as unconfirmed.

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
1. The app enrolls from the link (`mode=new`), through the `-interposeAutoEnroll` launch argument (simulator Debug
   builds only). The script does the admin step: it trusts the new account at the adapter (`interpose-adapter trust
   add-user`).
2. The test opens a normal-risk request, taps Approve, and waits for the adapter's verified ack.
3. It opens a high-risk request and checks that a tap does **not** approve it, then that a long press does.

The script checks the demo service's outcome afterwards. `scripts/e2e-cli.sh` is the same flow with the Go software
device instead of the app.

## Hubs: switching, leaving, resetting (Device tab)

| Action | What it does | Adapters |
|---|---|---|
| **Enroll with another hub…** (or open an `interpose://enroll` link while enrolled) | Enrolls with the new hub first, and forgets the old hub (and the account, if the link is for another user or a new account) only once that succeeds. Works for the same hub too, e.g. after its state was reset. | Keys are kept |
| **Leave this hub** | Forgets the hub, its token, adapter pins, the account and requests. Keys are kept. | To stop the device, remove it from the account on another device |
| **Reset device** | Leave the hub, and delete the keys | New keys must join the account again; remove the old device from the account first |

A hub that no longer knows the device (revoked, or its state wiped) answers 401. The app then says so and points to
Enroll with another hub. A new code from the same hub re-enrolls the same keys.

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
- An in-app **QR scanner**. The Camera app opening the `interpose://` link covers enrollment for now.
- **Untested on hardware:** Secure Enclave key creation with `.applicationPassword` and the PIN path. The simulator
  only exercises software keys.
- Device-side revocation handling and key rotation; Apple Watch approve.
