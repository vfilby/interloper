import ApproverKit
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var confirmReset = false

    var body: some View {
        List {
            Section {
                InsecureBanner().listRowInsets(EdgeInsets())
            }
            .listRowBackground(Color.clear)

            Section("Device") {
                if let pk = try? model.keys.publicKeys() {
                    LabeledContent("Device id") { Text(pk.deviceID).font(.footnote.monospaced()) }
                    LabeledContent("Approve key") { Text(Fingerprint.of(pk.approve)).font(.footnote.monospaced()) }
                    LabeledContent("Deny key") { Text(Fingerprint.of(pk.deny)).font(.footnote.monospaced()) }
                    LabeledContent("Encryption key") { Text(Fingerprint.of(pk.enc)).font(.footnote.monospaced()) }
                }
                LabeledContent("Key store", value: model.keys.kind.rawValue)
                LabeledContent("Hub", value: model.hubURL?.absoluteString ?? "—")
            }

            Section {
                ForEach(model.adapters) { a in
                    LabeledContent(a.id) { Text(a.fingerprint).font(.footnote.monospaced()) }
                }
                ForEach(model.conflicts) { c in
                    VStack(alignment: .leading) {
                        Text("\(c.id): the hub offers a different key").foregroundStyle(.red)
                        Text("pinned \(c.pinned), offered \(c.offered). Not used.").font(.footnote.monospaced())
                    }
                }
                Button("Check hub for new adapters") { Task { await model.refreshAdapters() } }
            } header: {
                Text("Pinned adapters")
            } footer: {
                Text("Requests are shown only when signed by a pinned adapter key. A changed key is never accepted: reset and re-enroll to change pins.")
            }

            Section {
                Button("Reset device", role: .destructive) { confirmReset = true }
            } footer: {
                Text("Deletes this device's keys, hub token and pins. Revoke the device at the hub and at each adapter too.")
            }
        }
        .navigationTitle("Device")
        .confirmationDialog("Delete this device's keys?", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("Reset device", role: .destructive) { model.reset() }
        }
    }
}
