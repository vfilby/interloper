import ApproverKit
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var confirmReset = false
    @State private var confirmLeave = false

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
            }

            Section {
                LabeledContent("Hub") { Text(model.hubURL?.absoluteString ?? "—").font(.footnote.monospaced()) }
                Button("Enroll with another hub…") {
                    model.pendingLink = nil
                    model.sheet = .switchHub
                }
                Button("Leave this hub", role: .destructive) { confirmLeave = true }
            } header: {
                Text("Hub")
            } footer: {
                Text("Moving or leaving keeps this device's keys: adapters that already trust it keep trusting it. To re-enroll at the same hub (e.g. after its state was reset), get a new code and use Enroll with another hub.")
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
                Text("Deletes this device's keys as well as leaving the hub. Every adapter must then trust the new keys; remove the old device there (`wga-adapter trust remove`) and revoke it at the hub.")
            }
        }
        .navigationTitle("Device")
        .confirmationDialog("Leave this hub?", isPresented: $confirmLeave, titleVisibility: .visible) {
            Button("Leave hub", role: .destructive) { model.leaveHub() }
        } message: {
            Text("Forgets the hub, its token and pinned adapters. The device keys stay. Revoke the device in the hub's management UI if it should not come back.")
        }
        .confirmationDialog("Delete this device's keys?", isPresented: $confirmReset, titleVisibility: .visible) {
            Button("Reset device", role: .destructive) { model.reset() }
        }
    }
}
