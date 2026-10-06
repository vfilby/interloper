import ApproverKit
import SwiftUI

struct InboxView: View {
    @EnvironmentObject var model: AppModel
    @State private var now = Date()

    var body: some View {
        List {
            Section {
                InsecureBanner().listRowInsets(EdgeInsets())
            }
            .listRowBackground(Color.clear)

            MembershipBanner()

            if !model.joins.isEmpty {
                Section {
                    ForEach(model.joins) { j in
                        NavigationLink(value: JoinRoute(deviceID: j.deviceId)) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(sanitize(j.name)).font(.headline)
                                Text(joinFingerprint(j)).font(.footnote.monospaced()).foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: {
                    Text("Devices asking to join \(model.user ?? "")")
                }
            }

            let live = model.requests.filter { !$0.record.isExpired(at: now) }
            Section("Pending") {
                if live.isEmpty {
                    Text("Nothing waiting").foregroundStyle(.secondary)
                }
                ForEach(live) { req in
                    NavigationLink(value: req.id) { RequestRow(req: req, now: now) }
                }
            }

            // Everything else this device has opened: decided, expired, or no longer listed by the hub.
            let history = model.history.filter { e in !live.contains { $0.id == e.id } }
            if !history.isEmpty {
                Section("History") {
                    ForEach(history) { e in
                        NavigationLink(value: e.id) { HistoryRow(entry: e, outcome: model.outcomes[e.id], now: now) }
                    }
                }
            }

            if !model.refused.isEmpty {
                Section {
                    ForEach(model.refused, id: \.self) { Text($0).font(.footnote).foregroundStyle(.red) }
                } header: {
                    Text("Refused (not shown)")
                } footer: {
                    Text("These did not open or verify against a pinned adapter key. They cannot be approved.")
                }
            }

            if let e = model.lastError {
                Section { Text(e).font(.footnote).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Requests")
        .navigationDestination(for: String.self) { id in
            if let req = model.requests.first(where: { $0.id == id }) ?? model.historyEntry(id)?.request {
                RequestDetailView(req: req)
            } else {
                Text("No longer pending").foregroundStyle(.secondary)
            }
        }
        .navigationDestination(for: JoinRoute.self) { route in
            if let j = model.joins.first(where: { $0.deviceId == route.deviceID }) {
                JoinDetailView(join: j)
            } else {
                Text("No longer asking to join").foregroundStyle(.secondary)
            }
        }
        .refreshable { await model.refresh() }
        .task {
            // Only the clock for expiry display; RootView does the polling (this task stops when a detail is pushed).
            while !Task.isCancelled {
                now = Date()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }
}

struct RequestRow: View {
    let req: OpenedRequest
    let now: Date

    var body: some View {
        let r = req.record
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                if r.isHighRisk { Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red) }
                Text(sanitize(r.title)).font(.headline).lineLimit(2)
            }
            HStack(spacing: 6) {
                Text(sanitize(r.adapter))
                Text("·")
                Text(sanitize(r.requester))
                Spacer()
                Text(Date(timeIntervalSince1970: TimeInterval(r.expiresAt)), style: .relative)
            }
            .font(.footnote).foregroundStyle(.secondary)
        }
    }
}

struct HistoryRow: View {
    let entry: HistoryEntry
    let outcome: Outcome?
    let now: Date

    var body: some View {
        let r = entry.record
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                if r.isHighRisk { Image(systemName: "exclamationmark.octagon.fill").foregroundStyle(.red) }
                Text(sanitize(r.title)).lineLimit(2)
            }
            HStack(spacing: 6) {
                if let approved = entry.approved {
                    Text(approved ? "You approved" : "You denied")
                    Text("·")
                }
                if let outcome {
                    OutcomeText(outcome: outcome)
                } else if r.isExpired(at: now) {
                    Text("expired")
                } else {
                    Text("no outcome seen")
                }
            }
            .font(.footnote).foregroundStyle(.secondary).lineLimit(1)
            Text(Date(timeIntervalSince1970: TimeInterval(r.createdAt)), format: .dateTime.month().day().hour().minute())
                .font(.caption).foregroundStyle(.tertiary)
        }
    }
}

struct OutcomeText: View {
    let outcome: Outcome?

    var body: some View {
        switch outcome {
        case .none: Text("waiting")
        case .sent: Text("sent, waiting for the adapter")
        case .final(let a): Text("\(a.outcome) (confirmed by \(sanitize(a.adapter)))")
            .foregroundStyle(a.outcome == "expired" ? Color.secondary : Color.green)
        case .note(let a):
            Text("\(a.outcome == "rejected" ? "Rejected by adapter" : "Service call failed"): \(sanitize(a.detail ?? "")). Still pending.")
                .foregroundStyle(.orange)
        case .unconfirmed(let why): Text("unconfirmed: \(why)").foregroundStyle(.orange)
        case .failed(let why): Text("not delivered: \(why)").foregroundStyle(.red)
        }
    }
}
