import ApproverKit
import SwiftUI
import UIKit

struct EnrollView: View {
    @EnvironmentObject var model: AppModel
    @State private var linkText = ""
    @State private var name = UIDevice.current.name
    @State private var pin = ""
    @State private var working = false

    private var link: EnrollmentLink? { model.pendingLink ?? EnrollmentLink(linkText) }
    private var needsPIN: Bool { !model.isInsecure }

    var body: some View {
        Form {
            Section {
                InsecureBanner().listRowInsets(EdgeInsets())
            }
            .listRowBackground(Color.clear)

            Section("Enrollment link") {
                if let l = model.pendingLink {
                    LabeledContent("Hub", value: l.hub.absoluteString)
                    LabeledContent("Code", value: l.code)
                } else {
                    TextField("wga://enroll?hub=…&code=…", text: $linkText, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.footnote.monospaced())
                    Text("Scan the QR code in the management UI with the Camera app, or paste the link shown under it.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }

            Section("This device") {
                TextField("Name", text: $name)
                if needsPIN {
                    SecureField("App PIN (6+ digits, Face ID fallback)", text: $pin)
                        .keyboardType(.numberPad)
                }
            }

            Section {
                Button {
                    guard let link else { return }
                    working = true
                    Task {
                        await model.enroll(link, name: name, pin: needsPIN ? pin : nil)
                        working = false
                    }
                } label: {
                    HStack {
                        Text("Enroll")
                        if working { Spacer(); ProgressView() }
                    }
                }
                .disabled(link == nil || working || name.isEmpty || (needsPIN && pin.count < 6))
            } footer: {
                Text("Creates this device's keys, signs its card (Face ID) and registers it with the hub. The hub cannot approve anything; each adapter must also be told to trust this device.")
            }

            if let e = model.lastError {
                Section { Text(e).foregroundStyle(.red).font(.footnote) }
            }
        }
        .navigationTitle("Enroll")
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
