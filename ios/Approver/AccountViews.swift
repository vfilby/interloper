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

/// The name in a join request's verified card (not the hub's copy beside it), made safe to show.
func joinName(_ j: HubJoin) -> String {
    guard let c = try? verifyCard(j.card), c.deviceId == j.deviceId else { return sanitize(j.name) }
    return sanitize(c.name)
}

/// Pending, removed or a refused roster: shown on top of the inbox.
struct MembershipBanner: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        if let e = model.rosterError {
            Section { Text(sanitize(e)).font(.footnote).foregroundStyle(.red) } footer: {
                Text("The last verified device list stays in use.")
            }
        }
        switch model.membership {
        case .pending where model.accountNeedsConfirmation:
            if let a = model.unconfirmedAccount { ConfirmAccountSection(account: a) }
        case .pending:
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Waiting for approval on another of \(model.user ?? "the account")'s devices.").font(.headline)
                    Text("This device's fingerprint — compare it there:").font(.footnote)
                    Text(model.deviceFingerprint ?? "—").font(.title3.monospaced().weight(.semibold))
                    if let a = model.unconfirmedAccount, model.rosterError == nil {
                        Text("The hub's account fingerprint, not confirmed: \(a). After approval you compare it with your other device; do not give it to an adapter before.")
                            .font(.caption).foregroundStyle(.secondary)
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

/// A joining device the hub's chain includes: the person compares the account fingerprint with a device already on the
/// account before it is pinned. The hub holds this device's card, so a chain of its own could include it too.
struct ConfirmAccountSection: View {
    @EnvironmentObject var model: AppModel
    let account: String
    @State private var working = false

    var body: some View {
        Section {
            VStack(alignment: .leading, spacing: 8) {
                Text("Confirm the account").font(.headline)
                Text("On a phone already on \(model.user ?? "the account"), open Device → Account. Does it show this account fingerprint?")
                    .font(.footnote)
                Text(account).font(.body.monospaced().weight(.semibold))
                    .accessibilityIdentifier("unconfirmed-account")
            }
            Button {
                working = true
                Task { await model.confirmAccount(account); working = false }
            } label: {
                Label("It matches", systemImage: "checkmark.shield")
            }
            .disabled(working)
            Button(role: .destructive) {
                working = true
                Task { await model.rejectAccount(account); working = false }
            } label: {
                Label("It is different", systemImage: "xmark.shield")
            }
            .disabled(working)
        } footer: {
            Text("Until you confirm, this device approves nothing and shows no account fingerprint to give an adapter. If they differ, the hub may have built a device list of its own: do not trust it anywhere, and leave this hub.")
        }
        .listRowBackground(Color.orange.opacity(0.15))
    }
}

/// Adapters the hub lists that are not pinned yet: pinned once the person compares the fingerprint with the adapter's.
struct OfferedAdaptersSection: View {
    @EnvironmentObject var model: AppModel
    @State private var trusting: PinnedAdapter?

    var body: some View {
        if !model.offeredAdapters.isEmpty {
            Section {
                ForEach(model.offeredAdapters) { a in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(sanitize(a.id))
                            Text(a.fingerprint).font(.footnote.monospaced()).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Trust…") { trusting = a }.buttonStyle(.borderless)
                    }
                }
            } header: {
                Text("New adapters" + (model.heldRequests > 0 ? " (\(model.heldRequests) requests waiting)" : ""))
            } footer: {
                Text("The hub lists these adapters. Trust one only if its fingerprint matches what the adapter prints (`interpose-adapter key`, or its log at start); its requests show after that.")
            }
            .confirmationDialog("Does \(trusting.map { sanitize($0.id) } ?? "") print \(trusting?.fingerprint ?? "")?",
                                isPresented: Binding(get: { trusting != nil }, set: { if !$0 { trusting = nil } }),
                                titleVisibility: .visible) {
                Button("It matches: trust it") {
                    guard let a = trusting else { return }
                    Task { await model.trustAdapter(a) }
                }
                Button("Cancel", role: .cancel) {}
            }
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
                LabeledContent("Name", value: joinName(join))
                Text(joinFingerprint(join)).font(.title2.monospaced().weight(.bold))
            } header: {
                Text("Asking to join \(model.user ?? "")")
            } footer: {
                Text("Compare with the new phone's screen. Approve only if they match and you are adding that phone yourself: an approved device can approve everything this account can.")
            }
            if let a = model.account {
                Section {
                    Text(a).font(.body.monospaced().weight(.semibold))
                } header: {
                    Text("Account fingerprint")
                } footer: {
                    Text("After approval the new phone asks whether this phone shows the same account fingerprint. Check it there.")
                }
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
            if let error { Section { Text(sanitize(error)).foregroundStyle(.red).font(.footnote) } }
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
            } else if model.accountNeedsConfirmation {
                Text("Not confirmed: compare it with your other device in the inbox.").foregroundStyle(.orange)
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
                    let isThis = c.deviceId == model.deviceID
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(sanitize(c.name)).fontWeight(isThis ? .semibold : .regular)
                                if isThis {
                                    Text("This device").font(.caption.weight(.semibold)).foregroundStyle(.tint)
                                        .padding(.horizontal, 6).padding(.vertical, 1)
                                        .background(Capsule().fill(.tint.opacity(0.15)))
                                        .accessibilityIdentifier("this-device-badge")
                                }
                            }
                            Text(fingerprint(c)).font(.footnote.monospaced()).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if head.devices.count > 1 && model.canApprove {
                            Button("Remove", role: .destructive) { removing = c }
                                .buttonStyle(.borderless)
                        }
                    }
                    .listRowBackground(isThis ? Color.accentColor.opacity(0.08) : nil)
                }
            } else {
                Text("No verified device list yet.").foregroundStyle(.secondary)
            }
            if let error { Text(sanitize(error)).font(.footnote).foregroundStyle(.red) }
            DisclosureGroup("This device's keys") { DeviceKeysRows() }
        } header: {
            Text("Devices on this account" + (model.head.map { " (roster \($0.roster.seq))" } ?? ""))
        } footer: {
            Text("Each device's fingerprint (4 groups) identifies it, e.g. when another of your devices approves it; adapters trust the account fingerprint above instead. Removing signs a new device list on this phone (Face ID). Adapters stop accepting the removed device as soon as they see it. The last device cannot be removed.")
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

/// This device's own keys, for checking against the hub or another device: collapsed under the device list.
struct DeviceKeysRows: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        if let pk = try? model.keys.publicKeys() {
            LabeledContent("Device id") { Text(pk.deviceID).font(.footnote.monospaced()) }
            // The same fingerprint the device list shows for this device; adapters trust the account fingerprint.
            LabeledContent("Approve key") { Text(Fingerprint.of(pk.approve)).font(.footnote.monospaced()) }
            LabeledContent("Deny key") { Text(Fingerprint.of(pk.deny)).font(.footnote.monospaced()) }
            LabeledContent("Encryption key") { Text(Fingerprint.of(pk.enc)).font(.footnote.monospaced()) }
        }
        LabeledContent("Key store", value: model.keys.kind.rawValue)
    }
}
