# TestFlight beta for the Interloper app

The app is **Interloper** (`com.eff3.interloper`), on team `ABCDE12345`, the same team as MigraLog. Builds are made
and uploaded by GitHub Actions: `.github/workflows/ios-testflight.yml`, modelled on MigraLog's release pipeline.
- **Signing:** manual, with the team's **Apple Distribution** certificate and an App Store profile named
  **Interloper App Store**.
- **Upload:** `xcodebuild -exportArchive` with an App Store Connect API key (`ios/ExportOptions.plist`).
- **Version:** tags `ios/v<major>.<minor>.<patch>`. Each run bumps the patch, and the build number is the patch.

## One-time setup

### 1. GitHub repository
Create a **private** repo for this code. Register Claude's deploy key on it with write access:
`~/.ssh/id_claude_git.pub`. Claude pushes with `cgit`.

### 2. Apple Developer (developer.apple.com → Certificates, Identifiers & Profiles)
1. **Identifiers → +, App IDs → App:** description `Interloper`, bundle id (explicit) `com.eff3.interloper`. No extra
   capabilities are needed yet. Push notifications will need one later.
2. **Profiles → +, Distribution → App Store Connect:**
   - App ID: `com.eff3.interloper`;
   - certificate: the team's existing **Apple Distribution** certificate (the one MigraLog uses);
   - profile name: exactly `Interloper App Store`.

   Download it.

### 3. App Store Connect (appstoreconnect.apple.com)
1. **Apps → + New App:** iOS, name `Interloper` (App Store names are global; if it is taken, use e.g.
   `Interloper Approvals`; the home-screen name stays "Interloper"), bundle id `com.eff3.interloper`, SKU `interloper`.
2. **TestFlight → Internal Testing → +:** group `Beta`, with **automatic distribution** on. Add yourself (and family
   members who should approve, once they are App Store Connect users).

### 4. Repository secrets (Settings → Secrets and variables → Actions)
The certificate and API key are the same as MigraLog's. GitHub cannot read secrets back, so take them from where
they are kept (1Password).

| Secret | Value |
|---|---|
| `SWIFT_CERTIFICATE_P12` | base64 of the Apple Distribution `.p12` (as for MigraLog) |
| `SWIFT_CERTIFICATE_PASSWORD` | its password |
| `INTERLOPER_PROVISIONING_PROFILE` | `base64 -i "Interloper_App_Store.mobileprovision"` |
| `ASC_KEY_ID`, `ASC_ISSUER_ID` | App Store Connect API key (role App Manager or higher; the MigraLog key works team-wide) |
| `ASC_API_KEY_P8` | the key's `.p8` text |
| `APPLE_TEAM_ID` | `ABCDE12345` |

With the GitHub CLI: `gh secret set INTERLOPER_PROVISIONING_PROFILE --repo <owner>/<repo> < profile.b64`, and so on.

## Releasing a beta

- **Starting a run:** Actions → **[iOS] TestFlight** → Run workflow. A push to `main` that touches `ios/` also starts
  one.
- **The run:** ApproverKit unit tests, archive, upload, then the `ios/v…` tag.
- **After upload:** App Store Connect processes the build (about 5–15 minutes). The `Beta` group then gets it, and
  testers install it from the TestFlight app. Builds expire after 90 days.

### Export compliance (asked on the first upload)
The app does not declare `ITSAppUsesNonExemptEncryption`, so App Store Connect asks. The facts:
- it encrypts message payloads and signs decisions with standard, published algorithms (HPKE: P-256 ECDH, HKDF,
  AES-GCM; ECDSA P-256; Ed25519 verification), all through Apple's CryptoKit;
- it uses nothing proprietary, and is not limited to authentication.

Under US export rules that is ordinary mass-market encryption: usually eligible for the mass-market exception, with no
licence needed for distribution outside embargoed countries. It is not "exempt" in Apple's narrow sense
(authentication only, or only the OS's own HTTPS), so answer that it uses encryption and is not exempt, choose the
standard-algorithms/mass-market path, and answer the rest as asked. This is not legal advice. Once you have settled
the answer, it can be put in `Info.plist` so App Store Connect stops asking.

## Using a TestFlight build

- **Reaching the server:** the phone must reach your Interloper server. Use its https address (e.g.
  `approvals.home.example`) on the LAN or VPN. A development hub on a Mac works over http on the local network
  (`http://<mac>.local:8741`).
- **Keys:** a TestFlight build uses the **Secure Enclave**: Face ID (current enrollment) or the app PIN set when
  connecting. Nothing is software-keyed as in the simulator. Hardware-only paths to watch:
  - key creation;
  - signing an approval;
  - the PIN fallback;
  - Face ID being asked twice when connecting a new account (card, then first roster).
- **Debug hooks:** none of the UI-test launch arguments exist in Release builds.
