import ApproverKit
import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State private var confirmReset = false
    @State private var confirmLeave = false
    @State private var busy = false
    @State private var failure: Failure?

    /// Telling the hub failed: say why, and offer to forget it on this phone only.
    struct Failure: Identifiable {
        let id = UUID()
        let message: String
        let deleteKeys: Bool
    }

    var body: some View {
        List {
            Section {
                InsecureBanner().listRowInsets(EdgeInsets())
            }
            .listRowBackground(Color.clear)

            Section("Device") {
                if let pk = try? model.keys.publicKeys() {
                    LabeledContent("Device id") { Text(pk.deviceID).font(.footnote.monospaced()) }
                    // The fingerprint the management UI and `wga-adapter trust add` show for this device.
                    LabeledContent("Fingerprint") { Text(Fingerprint.of(pk.approve)).font(.footnote.monospaced().weight(.semibold)) }
                    LabeledContent("Deny key") { Text(Fingerprint.of(pk.deny)).font(.footnote.monospaced()) }
                    LabeledContent("Encryption key") { Text(Fingerprint.of(pk.enc)).font(.footnote.monospaced()) }
                }
                LabeledContent("Key store", value: model.keys.kind.rawValue)
            }

            AccountSection()

            Section {
                LabeledContent("Hub") { Text(model.hubURL?.absoluteString ?? "—").font(.footnote.monospaced()) }
                if let e = model.pushError { Text(e).font(.footnote).foregroundStyle(.red) }
                Button("Connect to another server…") {
                    model.pendingLink = nil
                    model.sheet = .switchHub
                }
                Button("Leave this hub", role: .destructive) { confirmLeave = true }
            } header: {
                Text("Hub")
            } footer: {
                Text("Leaving removes this device at the hub and forgets the hub here; the device keys and the account's device list stay, so it can come back with a new code.")
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
                    .disabled(busy)
            } footer: {
                Text("Takes this device off its account and the hub, then deletes its keys. With new keys it must join an account again.")
            }
        }
        .navigationTitle("Device")
        .confirmationDialog("Leave this hub?", isPresented: $confirmLeave, titleVisibility: .visible) {
            Button("Leave hub", role: .destructive) { run(deleteKeys: false) { try await model.leaveHub() } }
        } message: {
            Text("The hub forgets this device; this phone forgets the hub, its token and pinned adapters. The device keys stay.")
        }
        .confirmationDialog("Delete this device's keys?", isPresented: $confirmReset, titleVisibility: .visible) {
            Button(model.resetEffect == .deletesAccount ? "Delete account and reset" : "Reset device", role: .destructive) {
                run(deleteKeys: true) { try await model.reset() }
            }
        } message: {
            switch model.resetEffect {
            case .deletesAccount:
                Text("This is the only device on \(model.user ?? "the account"). Resetting deletes the account at the hub: enrolling again starts a new account, which adapters must trust again.")
            case .removesThisDevice:
                Text("Signs a new device list without this device (Face ID), so it can no longer approve for \(model.user ?? "the account"), then deletes its keys.")
            case .none:
                Text("The hub forgets this device, then its keys are deleted.")
            }
        }
        .alert("The hub was not told", isPresented: Binding(get: { failure != nil }, set: { if !$0 { failure = nil } }),
               presenting: failure) { f in
            Button(f.deleteKeys ? "Reset this phone anyway" : "Leave on this phone anyway", role: .destructive) {
                model.forgetLocally(deleteKeys: f.deleteKeys)
            }
            Button("Cancel", role: .cancel) {}
        } message: { f in
            Text("\(f.message)\n\nGoing ahead only changes this phone: the hub keeps the device until an admin removes it in the management UI.")
        }
    }

    private func run(deleteKeys: Bool, _ op: @escaping () async throws -> Void) {
        busy = true
        Task {
            do { try await op() } catch { failure = Failure(message: error.localizedDescription, deleteKeys: deleteKeys) }
            busy = false
        }
    }
}
