import ApproverKit
import Foundation
import SwiftUI

/// What became of a decision this device sent.
enum Outcome: Equatable {
    case sent                  // posted; no ack yet
    case final(Ack)            // verified ack: approved, denied or expired
    case note(Ack)             // verified ack: rejected or failed. Still pending: decide again
    case unconfirmed(String)   // an ack arrived but did not verify
    case failed(String)        // the hub did not take the decision

    var isFinal: Bool { if case .final = self { return true } else { return false } }
    /// Approve / Deny stay available unless the request is settled or a decision is in flight.
    var allowsDecision: Bool {
        switch self {
        case .final, .sent: return false
        default: return true
        }
    }
}

struct PinnedAdapter: Identifiable, Equatable {
    var id: String
    var key: Data
    var fingerprint: String { Fingerprint.of(key) }
}

/// A hub claim that disagrees with a pin: never used, always shown.
struct AdapterConflict: Identifiable, Equatable {
    var id: String
    var pinned: String
    var offered: String
}

struct Decided: Identifiable, Equatable {
    var id: String
    var title: String
    var approve: Bool
    var at: Date
}

@MainActor
final class AppModel: ObservableObject {
    let keys: KeyStore = defaultKeyStore()
    var device: Device { Device(keys: keys) }

    @Published private(set) var hubURL: URL?
    @Published private(set) var token: String?
    @Published private(set) var adapters: [PinnedAdapter] = []
    @Published private(set) var conflicts: [AdapterConflict] = []
    @Published private(set) var requests: [OpenedRequest] = []
    /// Every request opened this session, kept after the hub stops listing it so its detail screen can show the outcome.
    private(set) var seen: [String: OpenedRequest] = [:]
    @Published private(set) var refused: [String] = []
    @Published private(set) var outcomes: [String: Outcome] = [:]
    @Published private(set) var decided: [Decided] = []
    @Published var lastError: String?
    @Published var pendingLink: EnrollmentLink?
    /// The one sheet RootView shows: enrolling with another hub, then the summary of an enrollment. One item, so the
    /// first can turn into the second without two sheets colliding.
    @Published var sheet: Sheet?

    enum Sheet: Identifiable, Equatable {
        case switchHub
        case summary(EnrollmentSummary)
        var id: String {
            switch self {
            case .switchHub: return "switch"
            case .summary(let s): return "summary-" + s.deviceFingerprint
            }
        }
    }

    private let secrets = KeychainStorage()
    private let defaults = UserDefaults.standard
    /// Hashes of the decisions sent per request, oldest first: a note counts only for the latest one.
    private var sentHashes: [String: [String]] = [:]
    private var ackSince: Int64 = 0

    struct EnrollmentSummary: Equatable {
        var deviceFingerprint: String
        var adapters: [PinnedAdapter]
    }

    init() {
        hubURL = defaults.url(forKey: "hubURL")
        token = (try? secrets.get("hub.token")).flatMap { String(data: $0, encoding: .utf8) }
        adapters = Self.loadPins(defaults)
    }

    var isEnrolled: Bool { hubURL != nil && token != nil && keys.hasKeys() }
    var isInsecure: Bool { keys.kind == .software }

    private var client: HubClient? {
        guard let hubURL else { return nil }
        return HubClient(base: hubURL, token: token)
    }

    private var pins: [String: Data] { Dictionary(uniqueKeysWithValues: adapters.map { ($0.id, $0.key) }) }

    // MARK: enrollment

    func enroll(_ link: EnrollmentLink, name: String, pin: String?) async {
        lastError = nil
        do {
            let keys = self.keys
            let card: Envelope = try await Task.detached {
                if !keys.hasKeys() { try keys.generate(pin: pin) }
                // Signing the card uses the approve key: Face ID / PIN on a device.
                return try Device(keys: keys).card(name: name, pin: pin)
            }.value
            let resp = try await HubClient(base: link.hub, token: nil).enroll(code: link.code, card: card)
            let ours = try device.deviceID()
            guard resp.deviceId == ours else {
                throw ProtocolError.mismatch("hub enrolled \(resp.deviceId), this device is \(ours)")
            }
            // Only now, with the new hub's token in hand, forget the old hub. Pins are per hub; keys are kept, so
            // adapters that already trust this device keep trusting it.
            if hubURL != link.hub { forgetHub() }
            try secrets.set("hub.token", Data(resp.token.utf8))
            defaults.set(link.hub, forKey: "hubURL")
            hubURL = link.hub
            token = resp.token
            await refreshAdapters()
            pendingLink = nil
            sheet = .summary(EnrollmentSummary(deviceFingerprint: Fingerprint.of(try keys.publicKeys().approve),
                                               adapters: adapters))
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Pins adapters the hub lists for the first time (trust on first use). A different key for a pinned id is a
    /// conflict: it is shown and never used.
    func refreshAdapters() async {
        guard let client else { return }
        do {
            var pinned = adapters
            var found: [AdapterConflict] = []
            for a in try await client.adapters() {
                let key = try B64.decode(a.key)
                guard key.count == 32 else { continue }
                if let p = pinned.first(where: { $0.id == a.id }) {
                    if p.key != key { found.append(AdapterConflict(id: a.id, pinned: p.fingerprint, offered: Fingerprint.of(key))) }
                } else {
                    pinned.append(PinnedAdapter(id: a.id, key: key))
                }
            }
            adapters = pinned.sorted { $0.id < $1.id }
            conflicts = found
            Self.savePins(adapters, defaults)
        } catch {
            lastError = error.localizedDescription
        }
    }

    // MARK: inbox

    func refresh() async {
        guard isEnrolled, let client else { return }
        do {
            var opened: [OpenedRequest] = []
            var bad: [String] = []
            for l in try await client.requests() {
                do {
                    opened.append(try device.open(l, pinned: pins))
                } catch {
                    bad.append("\(l.adapter)/\(l.id): \(error.localizedDescription)")
                }
            }
            requests = opened.sorted { $0.record.createdAt > $1.record.createdAt }
            for r in opened { seen[r.id] = r }
            refused = bad

            applyAcks(try await client.acks(since: ackSince))
            lastError = nil
        } catch HubClient.HubError.http(401, _) {
            lastError = "The hub no longer recognizes this device: it was revoked, or the hub's state was reset. "
                + "Get a new enrollment code, then Device → Enroll with another hub (the same hub works too)."
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// Final acks (approved, denied, expired) settle a request whoever decided it. Notes (rejected, failed) count
    /// only when they answer this device's latest decision; older or foreign ones are dropped.
    private func applyAcks(_ acks: [HubAck]) {
        var verified: [(key: String, ack: Ack)] = []
        for a in acks {
            let key = "\(a.adapter)/\(a.requestId)"
            do {
                verified.append((key, try device.verifyAck(a, pinned: pins)))
            } catch {
                if outcomes[key]?.isFinal != true, sentHashes[key] != nil { outcomes[key] = .unconfirmed(error.localizedDescription) }
            }
        }
        var maxTS = ackSince
        for (key, ack) in verified.sorted(by: { $0.ack.ts < $1.ack.ts }) {
            maxTS = max(maxTS, ack.ts)
            if outcomes[key]?.isFinal == true { continue }
            if ack.isFinal {
                outcomes[key] = .final(ack)
            } else if let latest = sentHashes[key]?.last, ack.decisionHash == latest {
                outcomes[key] = .note(ack)
            }
        }
        // Overlap by a few seconds so acks written in the same second as the last one seen are not missed.
        ackSince = max(ackSince, maxTS - 5)
    }

    func decide(_ req: OpenedRequest, approve: Bool, pin: String? = nil) async {
        guard let client else { return }
        let keys = self.keys
        do {
            // Off the main thread: the approve key's Face ID prompt blocks the signing call.
            let env = try await Task.detached { try Device(keys: keys).decide(req, approve: approve, pin: pin) }.value
            sentHashes[req.id, default: []].append(B64.encode(sha256(try B64.decode(env.payload))))
            try await client.postDecision(DecisionPost(adapter: req.record.adapter, requestId: req.record.id, decision: env))
            outcomes[req.id] = .sent
            decided.removeAll { $0.id == req.id }
            decided.insert(Decided(id: req.id, title: req.record.title, approve: approve, at: Date()), at: 0)
            // The adapter usually answers within a second or two: poll quickly for the ack instead of waiting for the
            // regular 5 s cycle.
            for _ in 0..<15 {
                try? await Task.sleep(for: .seconds(1))
                await refresh()
                if outcomes[req.id]?.isFinal == true { break }
            }
        } catch {
            outcomes[req.id] = .failed(error.localizedDescription)
        }
    }

    // MARK: reset

    /// Leaves the hub: token, hub URL, pins and everything seen through it. The device keys stay, so enrolling again
    /// (here or at another hub) needs no new `trust add` at adapters that already trust this device.
    func leaveHub() {
        forgetHub()
        lastError = nil
    }

    /// Leaves the hub and deletes the device keys. Every adapter must then be told to trust the new keys.
    func reset() {
        try? keys.reset()
        forgetHub()
        lastError = nil
    }

    private func forgetHub() {
        try? secrets.delete("hub.token")
        defaults.removeObject(forKey: "hubURL")
        defaults.removeObject(forKey: "pinnedAdapters")
        hubURL = nil
        token = nil
        adapters = []
        conflicts = []
        requests = []
        seen = [:]
        refused = []
        outcomes = [:]
        decided = []
        sentHashes = [:]
        ackSince = 0
    }

    // MARK: pins on disk (public keys: UserDefaults is enough)

    private static func loadPins(_ d: UserDefaults) -> [PinnedAdapter] {
        guard let m = d.dictionary(forKey: "pinnedAdapters") as? [String: String] else { return [] }
        return m.compactMap { id, k in (try? B64.decode(k)).map { PinnedAdapter(id: id, key: $0) } }.sorted { $0.id < $1.id }
    }

    private static func savePins(_ a: [PinnedAdapter], _ d: UserDefaults) {
        d.set(Dictionary(uniqueKeysWithValues: a.map { ($0.id, B64.encode($0.key)) }), forKey: "pinnedAdapters")
    }
}
