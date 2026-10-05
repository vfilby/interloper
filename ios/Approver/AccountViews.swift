import ApproverKit
import SwiftUI

struct JoinRoute: Hashable {
    var deviceID: String
}

/// The fingerprint a join request's card shows, or why it cannot be shown. The card is verified, not trusted.
func joinFingerprint(_ j: HubJoin) -> String {
    guard let c = try? verifyCard(j.card), c.deviceId == j.deviceId, let ak = try? B64.decode(c.approveKey) else {
        return "card does not verify"
    }
    return Fingerprint.of(ak)
}

/// Pending, removed or a refused roster: shown on top of the inbox.
struct MembershipBanner: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        if let e = model.rosterError {
            Section { Text(e).font(.footnote).foregroundStyle(.red) } footer: {
                Text("The last verified device list stays in use.")
            }
        }
        switch model.membership {
        case .pending:
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Waiting for approval on another of \(model.user ?? "the account")'s devices.").font(.headline)
                    Text("This device's fingerprint — compare it there:").font(.footnote)
                    Text(model.deviceFingerprint ?? "—").font(.title3.monospaced().weight(.semibold))
                    if let a = model.unconfirmedAccount {
                        Text("Account fingerprint (unconfirmed until approved): \(a)").font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .listRowBackground(Color.orange.opacity(0.15))
        case .removed:
            Section {
                Text("This device was removed from \(model.user ?? "its account"). It can no longer approve anything.")
                    .foregroundStyle(.red)
            }
        case .member, .unknown:
            EmptyView()
        }
    }
}

/// A device asking to join: approve it here (this device signs the next roster with Face ID).
struct JoinDetailView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let join: HubJoin
    @State private var working = false
    @State private var error: String?

    var body: some View {
        List {
            Section {
                LabeledContent("Name", value: sanitize(join.name))
                Text(joinFingerprint(join)).font(.title2.monospaced().weight(.bold))
            } header: {
                Text("Asking to join \(model.user ?? "")")
            } footer: {
                Text("Compare with the new phone's screen. Approve only if they match and you are adding that phone yourself: an approved device can approve everything this account can.")
            }
            Section {
                Button {
                    working = true
                    error = nil
                    Task {
                        do {
                            try await model.approveJoin(join)
                            dismiss()
                        } catch {
                            self.error = error.localizedDescription
                        }
                        working = false
                    }
                } label: {
                    HStack {
                        Label("Approve this device", systemImage: "faceid")
                        if working { Spacer(); ProgressView() }
                    }
                }
                .disabled(working || !model.canApprove || joinFingerprint(join) == "card does not verify")
                Button("Ignore", role: .cancel) { dismiss() }
            }
            if let error { Section { Text(error).foregroundStyle(.red).font(.footnote) } }
        }
        .navigationTitle("Join request")
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// Settings: the account and its devices, from the last verified roster.
struct AccountSection: View {
    @EnvironmentObject var model: AppModel
    @State private var removing: DeviceCard?
    @State private var error: String?

    var body: some View {
        Section {
            LabeledContent("User id", value: model.user ?? "—")
            if let a = model.account {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Account fingerprint").font(.footnote).foregroundStyle(.secondary)
                    Text(a).font(.body.monospaced().weight(.semibold))
                        .textSelection(.enabled) // long-press to copy
                }
            } else {
                Text("Not confirmed yet (waiting for approval).").foregroundStyle(.orange)
            }
        } header: {
            Text("Account")
        } footer: {
            Text("Give an adapter this user id and account fingerprint (8 groups of 4) to trust the account: `trust add-user <user id> <account fingerprint>`. It then trusts every device on the account.")
        }

        Section {
            if let head = model.head {
                ForEach(head.roster.members.compactMap { head.devices[$0.card.kid] }, id: \.deviceId) { c in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(sanitize(c.name) + (c.deviceId == model.deviceID ? " (this device)" : ""))
                            Text(fingerprint(c)).font(.footnote.monospaced()).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if head.devices.count > 1 && model.canApprove {
                            Button("Remove", role: .destructive) { removing = c }
                                .buttonStyle(.borderless)
                        }
                    }
                }
            } else {
                Text("No verified device list yet.").foregroundStyle(.secondary)
            }
            if let error { Text(error).font(.footnote).foregroundStyle(.red) }
        } header: {
            Text("Devices on this account" + (model.head.map { " (roster \($0.roster.seq))" } ?? ""))
        } footer: {
            Text("Removing signs a new device list on this phone (Face ID). Adapters stop accepting the removed device as soon as they see it. The last device cannot be removed.")
        }
        .confirmationDialog("Remove \(removing.map { sanitize($0.name) } ?? "")?", isPresented: Binding(
            get: { removing != nil }, set: { if !$0 { removing = nil } }), titleVisibility: .visible) {
            Button("Remove device", role: .destructive) {
                guard let c = removing else { return }
                Task {
                    do { try await model.removeDevice(c.deviceId); error = nil } catch { self.error = error.localizedDescription }
                }
            }
        } message: {
            Text("It will no longer be able to approve anything for \(model.user ?? "this account").")
        }
    }

    private func fingerprint(_ c: DeviceCard) -> String {
        (try? B64.decode(c.approveKey)).map(Fingerprint.of) ?? "?"
    }
}
