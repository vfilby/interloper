# TestFlight beta for the Interloper app

The app is **Interloper** (`com.eff3.interloper`), on team `43DNX2P3T6`, the same team as MigraLog. Builds are made
and uploaded by GitHub Actions: `.github/workflows/ios-testflight.yml`, modelled on MigraLog's release pipeline.
- **Signing:** manual, with the team's **Apple Distribution** certificate and an App Store profile named
  **Interloper App Store**.
- **Upload:** `xcodebuild -exportArchive` with an App Store Connect API key (`ios/ExportOptions.plist`).
- **Version:** tags `ios/v<major>.<minor>.<patch>`. Each run bumps the patch, and the build number is the patch.

## One-time setup

### 1. GitHub repository
The repo is `vfilby/interpose` (**public**: no internal hostnames, IPs or keys in it). Claude pushes with `cgit`,
using its per-repo deploy key.

### 2. Apple Developer (developer.apple.com → Certificates, Identifiers & Profiles)
1. **Identifiers → +, App IDs → App:** description `Interloper`, bundle id (explicit) `com.eff3.interloper`. No extra
   capabilities are needed yet. Push notifications will need one later.
2. **Profiles → +, Distribution → App Store Connect:**
   - App ID: `com.eff3.interloper`;
   - certificate: the team's existing **Apple Distribution** certificate (the one MigraLog uses). Not "iOS
     Distribution" (the older type) and not "Developer ID Application" (Mac apps outside the App Store): the build
     signs as `Apple Distribution`. If there are several, match the expiry date of the one in your keychain;
   - profile name: exactly `Interloper App Store`.

   Download it.

### 3. App Store Connect (appstoreconnect.apple.com)
1. **Apps → + New App:** iOS, name `Interloper` (App Store names are global; if it is taken, use e.g.
   `Interloper Approvals`; the home-screen name stays "Interloper"), bundle id `com.eff3.interloper`, SKU `interloper`.
2. **TestFlight → Internal Testing → +:** group `Beta`, with **automatic distribution** on. Add yourself (and family
   members who should approve, once they are App Store Connect users).

### 4. Repository secrets (Settings → Secrets and variables → Actions)
GitHub cannot read secrets back, so they cannot be copied from MigraLog's repo. Instead:
- **Certificate:** Keychain Access → login → My Certificates → right-click
  `Apple Distribution: <name> (43DNX2P3T6)` → Export as `.p12`, with a new password.
- **API key:** App Store Connect → Users and Access → Integrations → App Store Connect API → Team Keys → generate
  an **App Manager** key (e.g. `Interloper CI`). The `.p8` downloads **once**; the Issuer ID is at the top of the page.
- Keep the `.p12`, its password, the `.p8`, Key ID and Issuer ID together in 1Password.

| Secret | Value |
|---|---|
| `SWIFT_CERTIFICATE_P12` | base64 of the Apple Distribution `.p12` (as for MigraLog) |
| `SWIFT_CERTIFICATE_PASSWORD` | its password |
| `INTERLOPER_PROVISIONING_PROFILE` | `base64 -i "Interloper_App_Store.mobileprovision"` |
| `ASC_KEY_ID`, `ASC_ISSUER_ID` | App Store Connect API key (role App Manager or higher; the MigraLog key works team-wide) |
| `ASC_API_KEY_P8` | the key's `.p8` text |
| `APPLE_TEAM_ID` | `43DNX2P3T6` |

With the GitHub CLI (quote filenames: exported ones contain spaces and parentheses):
```
gh secret set APPLE_TEAM_ID -R vfilby/interpose -b 43DNX2P3T6
base64 -i "Interloper_App_Store.mobileprovision" | gh secret set INTERLOPER_PROVISIONING_PROFILE -R vfilby/interpose
base64 -i "<exported>.p12" | gh secret set SWIFT_CERTIFICATE_P12 -R vfilby/interpose
pbpaste | gh secret set SWIFT_CERTIFICATE_PASSWORD -R vfilby/interpose   # copy the password first
pbpaste | gh secret set ASC_ISSUER_ID -R vfilby/interpose                # copy the Issuer ID first
gh secret set ASC_KEY_ID -R vfilby/interpose -b <KEYID>
gh secret set ASC_API_KEY_P8 -R vfilby/interpose < "AuthKey_<KEYID>.p8"
```
- **Use `pbpaste |`, not a bare `gh secret set NAME`:** in some shells `gh` does not prompt and silently reads stdin,
  which is easy to get wrong.
- **Check the password matches the file before setting it:**
  `openssl pkcs12 -legacy -in "<exported>.p12" -nokeys -passin "pass:$(pbpaste)" >/dev/null && echo OK`.
- **Read a failed signing step's log:** `CERT_P12:` shown blank means the secret is empty (a wrong path in the
  `base64` line); "passphrase … not correct" means the password secret does not match the `.p12`.

### 5. Push notifications (APNs)
The app asks for permission once it is enrolled and sends its APNs token to the hub. The hub sends a fixed text,
never request content.
1. **Identifiers → `com.eff3.interloper` → Capabilities:** tick **Push Notifications**, then Save. (No certificate:
   the hub uses a key, below.)
2. **Profiles → Interloper App Store → Edit → Save**, download it, and update the secret:
   `base64 -i "Interloper_App_Store.mobileprovision" | gh secret set INTERLOPER_PROVISIONING_PROFILE -R vfilby/interpose`.
   An old profile without push makes the archive step fail ("doesn't include the aps-environment entitlement").
3. **Keys → +:** name `Interloper APNs`, tick **Apple Push Notifications service (APNs)**, environment **Sandbox &
   Production**, then download `AuthKey_<KEYID>.p8`. It downloads **once**; keep it with the signing material in
   1Password. It goes to the hub, not to GitHub: `wga-hub -apns-key-file … -apns-key-id <KEYID>`.

Debug builds from Xcode use APNs' development environment and TestFlight builds production; the app tells the hub
which, so one key serves both.

## Releasing a beta

- **Starting a run:** Actions → **[iOS] TestFlight** → Run workflow. A push to `main` that touches `ios/` also starts
  one.
- **The run:** ApproverKit unit tests, archive, upload, then the `ios/v…` tag.
- **After upload:** App Store Connect processes the build (about 5–15 minutes). The `Beta` group then gets it, and
  testers install it from the TestFlight app. Builds expire after 90 days.

### Export compliance
`ITSAppUsesNonExemptEncryption` is `false` in `project.yml`, so App Store Connect does not ask. The reasoning, for
when it changes:
- The app encrypts and signs with standard algorithms (HPKE: P-256 ECDH, HKDF, AES-GCM; ECDSA P-256; Ed25519), but
  only through Apple's CryptoKit and Security frameworks. It has no third-party or own crypto.
- If App Store Connect asks "What type of encryption algorithms does your app implement?", the answer is **None of
  the algorithms mentioned above**. "Standard encryption algorithms" means *instead of, or in addition to,* Apple's
  operating-system encryption, i.e. shipping your own implementation; that path asks for documentation.
- If the app ever bundles its own crypto (e.g. a third-party library), remove the flag and answer again.

This is not legal advice.

## Using a TestFlight build

- **Reaching the server:** the phone must reach your Interloper server. Use its https address (e.g.
  `interpose-hub.home.example`) on the LAN or VPN. A development hub on a Mac works over http on the local network
  (`http://<mac>.local:8741`).
- **Keys:** a TestFlight build uses the **Secure Enclave**: Face ID (current enrollment) or the app PIN set when
  connecting. Nothing is software-keyed as in the simulator. Hardware-only paths to watch:
  - key creation;
  - signing an approval;
  - the PIN fallback;
  - Face ID being asked twice when connecting a new account (card, then first roster).
- **Debug hooks:** none of the UI-test launch arguments exist in Release builds.
