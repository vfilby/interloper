import ApproverKit
import SwiftUI
import UIKit

struct EnrollView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    /// Shown as a sheet from an enrolled device: moving to another hub, or re-enrolling at the same one.
    var switching = false
    @State private var linkText = ""
    @State private var name = UIDevice.current.name
    @State private var pin = ""
    @State private var working = false

    private var link: EnrollmentLink? { model.pendingLink ?? EnrollmentLink(linkText) }
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
                    LabeledContent("Current hub", value: model.hubURL?.absoluteString ?? "—")
                } footer: {
                    Text("Enrolling here replaces the current hub once the new one accepts this device. The device keys are kept, so adapters that already trust this device keep trusting it; requests and pins from the old hub are dropped.")
                }
            }

            Section("Enrollment link") {
                if let l = model.pendingLink {
                    LabeledContent("Hub", value: l.hub.absoluteString)
                    LabeledContent("Code", value: l.code)
                } else {
                    TextField("wga://enroll?hub=…&code=…", text: $linkText, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.footnote.monospaced())
                    PasteButton(payloadType: String.self) { strings in
                        if let s = strings.first { linkText = s.trimmingCharacters(in: .whitespacesAndNewlines) }
                    }
                    Text("Scan the QR code in the management UI with the Camera app, or paste the link shown under it. Simulator: run the `xcrun simctl openurl` command shown on the enroll page.")
                        .font(.footnote).foregroundStyle(.secondary)
                    if !linkText.isEmpty && EnrollmentLink(linkText) == nil {
                        Text("Not an enrollment link.").font(.footnote).foregroundStyle(.red)
                    }
                }
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
                    guard let link else { return }
                    working = true
                    Task {
                        await model.enroll(link, name: name, pin: pin.isEmpty ? nil : pin)
                        working = false
                    }
                } label: {
                    HStack {
                        Text(switching ? "Enroll with this hub" : "Enroll")
                        if working { Spacer(); ProgressView() }
                    }
                }
                .disabled(link == nil || working || name.isEmpty || (needsPIN && pin.count < 6))
            } footer: {
                Text(newKeys
                     ? "Creates this device's keys, signs its card (Face ID) and registers it with the hub. The hub cannot approve anything; each adapter must also be told to trust this device."
                     : "Signs this device's card with its existing key (Face ID) and registers it with the hub. Adapters that already trust this device need nothing new.")
            }

            if let e = model.lastError {
                Section { Text(e).foregroundStyle(.red).font(.footnote) }
            }
        }
        .navigationTitle(switching ? "Enroll with another hub" : "Enroll")
        .toolbar {
            if switching {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
        }
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
                    Text("Must match what the management UI and each adapter's `trust add` print for this device.")
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
                    Text("Pinned on first sight. Compare with the fingerprint each adapter prints at start.")
                }
            }
            .navigationTitle("Enrolled")
            .toolbar { Button("Done") { dismiss() } }
        }
    }
}
