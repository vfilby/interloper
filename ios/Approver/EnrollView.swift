import ApproverKit
import AuthenticationServices
import SwiftUI
import UIKit

/// Onboarding, in three steps:
///   1. Interpose server: the person enters its address; the app checks it is one (/app/hello).
///   2. Continue on the server: the person signs in there (two-factor), and the server hands the app an enrollment
///      link for them: a new account the first time, otherwise another device to approve on one they have.
///   3. Connect this device: name it (and set the app PIN on a device with a Secure Enclave), then enroll.
/// An enrollment link or QR code from the management page is the other way in; it goes straight to step 3.
/// Also used as a sheet from an enrolled device, to connect it to another server (or again to the same one).
struct EnrollView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.webAuthenticationSession) private var webAuth
    var switching = false

    @AppStorage("signInAddress") private var address = ""
    @State private var server: (base: URL, info: ServerInfo)?
    @State private var localUser = ""
    @State private var usingLink = false
    @State private var linkText = ""
    @State private var scanning = false
    @State private var name = UIDevice.current.name
    @State private var pin = ""
    @State private var busy = false
    @State private var stepError: String?

    private var link: EnrollmentLink? { model.pendingLink ?? (usingLink ? EnrollmentLink(linkText) : nil) }
    /// New Secure Enclave keys need the app PIN set now. Existing keys only use it as Face ID's fallback.
    private var newKeys: Bool { !model.keys.hasKeys() }
    private var needsPIN: Bool { !model.isInsecure && newKeys }

    var body: some View {
        Form {
            Section {
                InsecureBanner().listRowInsets(EdgeInsets())
            }
            .listRowBackground(Color.clear)

            if switching {
                Section {
                    LabeledContent("Connected to", value: model.hubURL?.host() ?? "—")
                } footer: {
                    Text("Connecting here replaces the current server once the new one accepts this device. The device keys are kept, so adapters that trust your account keep trusting this device.")
                }
            }

            if model.pendingLink != nil {
                connectStep
            } else if usingLink {
                linkStep
                if link != nil { connectStep }
            } else if let server {
                signInStep(server.base, server.info)
            } else {
                serverStep
            }

            if let e = stepError ?? model.lastError {
                Section { Text(e).foregroundStyle(.red).font(.footnote) }
            }
        }
        .navigationTitle(switching ? "Connect to a server" : "Connect to Interpose")
        .toolbar {
            if switching {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
        }
    }

    // MARK: step 1: the server

    private var serverStep: some View {
        Group {
            Section {
                TextField("interpose-hub.home.example", text: $address)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .submitLabel(.continue)
                    .onSubmit { Task { await checkServer() } }
                Button {
                    Task { await checkServer() }
                } label: {
                    HStack {
                        Text("Continue")
                        if busy { Spacer(); ProgressView() }
                    }
                }
                .disabled(SignIn.base(address) == nil || busy)
            } header: {
                Text("Interpose server")
            } footer: {
                Text("The address of your Interpose server: the page you manage it from.")
            }
            Section {
                if QRScannerSheet.isAvailable {
                    Button("Scan an enrollment QR code") { usingLink = true; stepError = nil; scanning = true }
                }
                Button("I have an enrollment link") { usingLink = true; stepError = nil }
            } footer: {
                Text("From the server's management page.")
            }
        }
    }

    private func checkServer() async {
        guard let base = SignIn.base(address), !busy else { return }
        busy = true
        stepError = nil
        defer { busy = false }
        do {
            server = (base, try await SignIn.hello(base))
        } catch {
            stepError = error.localizedDescription
        }
    }

    // MARK: step 2: continue on the server

    @ViewBuilder
    private func signInStep(_ base: URL, _ info: ServerInfo) -> some View {
        Section {
            LabeledContent("Server", value: base.host() ?? base.absoluteString)
            Button("Change server") { server = nil; stepError = nil }
        }
        Section {
            if info.isLocal {
                TextField("Your user id", text: $localUser)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
            }
            Button {
                Task { await continueOnServer(base, info) }
            } label: {
                HStack {
                    Label("Continue on \(base.host() ?? "the server")", systemImage: "person.badge.key")
                    if busy { Spacer(); ProgressView() }
                }
            }
            .disabled(busy || (info.isLocal && localUser.isEmpty))
        } header: {
            Text("Register this device")
        } footer: {
            Text(info.isLocal
                 ? "A development server without sign-in: it registers this device for the user id you give."
                 : "You sign in on the server with your usual account (two-factor) and it registers this device for you: a new account the first time, otherwise another device that one of your phones approves. Nothing is remembered here: you sign in each time.")
        }
    }

    /// Opens the server in a private browser session (no shared cookies, no "wants to sign in" prompt) and waits for
    /// it to send back an interpose://enroll link.
    private func continueOnServer(_ base: URL, _ info: ServerInfo) async {
        busy = true
        stepError = nil
        defer { busy = false }
        do {
            let back = try await webAuth.authenticate(using: SignIn.enrollURL(base, user: info.isLocal ? localUser : nil),
                                                      callbackURLScheme: "interpose", preferredBrowserSession: .ephemeral)
            guard let l = EnrollmentLink(back.absoluteString) else {
                stepError = "The server answered with something that is not an enrollment link."
                return
            }
            model.pendingLink = l
        } catch {
            if (error as? ASWebAuthenticationSessionError)?.code != .canceledLogin {
                stepError = error.localizedDescription
            }
        }
    }

    // MARK: the other way in: a link

    private var linkStep: some View {
        Section {
            TextField("interpose://enroll?hub=…&code=…", text: $linkText, axis: .vertical)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .font(.footnote.monospaced())
            if QRScannerSheet.isAvailable {
                Button("Scan QR code", systemImage: "qrcode.viewfinder") { scanning = true }
            }
            PasteButton(payloadType: String.self) { strings in
                if let s = strings.first { linkText = s.trimmingCharacters(in: .whitespacesAndNewlines) }
            }
            if !linkText.isEmpty, let err = linkError(linkText) {
                Text(err).font(.footnote).foregroundStyle(.red)
            }
            Button("Use the server address instead") { usingLink = false; linkText = "" }
        } header: {
            Text("Enrollment link")
        } footer: {
            Text("Scan the QR code on the server's management page, or paste the link shown under it. Simulator: run the `xcrun simctl openurl` command shown on the enroll page.")
        }
        .sheet(isPresented: $scanning) {
            QRScannerSheet { linkText = $0 }
        }
    }

    // MARK: step 3: connect this device

    @ViewBuilder
    private var connectStep: some View {
        if let l = link {
            Section {
                LabeledContent("Server", value: l.hub.host() ?? l.hub.absoluteString)
                LabeledContent("Account", value: l.user)
                LabeledContent("Joins as", value: l.mode == .new ? "first device of a new account" : "another device (needs approval)")
                if model.pendingLink != nil {
                    Button("Start over") { model.pendingLink = nil; server = nil; usingLink = false }
                }
            } header: {
                Text("Connect this device")
            }
            Section("This device") {
                TextField("Name", text: $name)
                if needsPIN {
                    SecureField("App PIN (6+ digits, Face ID fallback)", text: $pin)
                        .keyboardType(.numberPad)
                } else if !model.isInsecure {
                    SecureField("App PIN (only if Face ID is unavailable)", text: $pin)
                        .keyboardType(.numberPad)
                }
            }
            Section {
                Button {
                    busy = true
                    Task {
                        await model.enroll(l, name: name, pin: pin.isEmpty ? nil : pin)
                        busy = false
                    }
                } label: {
                    HStack {
                        Text("Connect this device")
                        if busy { Spacer(); ProgressView() }
                    }
                }
                .disabled(busy || name.isEmpty || (needsPIN && pin.count < 6))
            } footer: {
                if l.mode == .join {
                    Text("Signs this device's card (Face ID) and asks to join the account. It can approve nothing until a device already on the account approves it there; compare this device's fingerprint on both screens.")
                } else {
                    Text("Creates this device's keys if needed, signs its card and the account's first roster (Face ID) and registers them. The server cannot add devices to the account; adapters trust the account by its fingerprint.")
                }
            }
        }
    }

    private func linkError(_ s: String) -> String? {
        do { _ = try EnrollmentLink(parsing: s); return nil } catch { return error.localizedDescription }
    }
}

/// After enrolling: the fingerprints the admin compares with the management UI and with `adapter trust add`.
struct EnrollmentSummaryView: View {
    let summary: AppModel.EnrollmentSummary
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text(summary.deviceFingerprint).font(.title3.monospaced())
                } header: {
                    Text("Device fingerprint")
                } footer: {
                    Text(summary.account == nil
                         ? "Compare it with what the device approving this one shows for the join request."
                         : "Must match what the management UI shows for this device.")
                }
                Section {
                    LabeledContent("Account", value: summary.user)
                    if let a = summary.account {
                        Text(a).font(.footnote.monospaced().weight(.semibold))
                    } else {
                        Text("Waiting for approval on another of \(summary.user)'s devices.").foregroundStyle(.orange)
                    }
                } header: {
                    Text("Account fingerprint")
                } footer: {
                    if summary.account != nil {
                        Text("Adapters trust the account by this fingerprint: `interpose-adapter trust add-user \(summary.user) \(summary.account ?? "")`.")
                    }
                }
                Section {
                    if summary.adapters.isEmpty {
                        Text("None yet").foregroundStyle(.secondary)
                    }
                    ForEach(summary.adapters) { a in
                        LabeledContent(a.id) { Text(a.fingerprint).font(.footnote.monospaced()) }
                    }
                } header: {
                    Text("Adapters pinned")
                } footer: {
                    Text(summary.account == nil
                         ? "Pinned on first sight, once this device is admitted. Compare with the fingerprint each adapter prints at start."
                         : "Pinned on first sight. Compare with the fingerprint each adapter prints at start.")
                }
            }
            .navigationTitle("Enrolled")
            .toolbar { Button("Done") { dismiss() } }
        }
    }
}
