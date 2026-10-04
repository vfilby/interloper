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

/// This device's place in its user's roster, from the last verified head.
enum Membership: Equatable {
    case unknown   // no verified roster yet
    case pending   // enrolled with a join code; not in the roster yet
    case member
    case removed   // was a member, no longer is
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

    // Account (docs/PROTOCOL.md "Users and rosters").
    @Published private(set) var user: String?
    /// Pinned account fingerprint: set at genesis, or on first sight of a verified chain that includes this device.
    @Published private(set) var account: String?
    /// The account fingerprint of the hub's chain while this device is not yet a member (not pinned; for comparison).
    @Published private(set) var unconfirmedAccount: String?
    @Published private(set) var head: Head?
    @Published private(set) var membership: Membership = .unknown
    @Published private(set) var joins: [HubJoin] = []
    @Published private(set) var rosterError: String?

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
        var user: String
        /// Pinned account fingerprint; nil while a join waits for approval.
        var account: String?
    }

    init() {
        hubURL = defaults.url(forKey: "hubURL")
        token = (try? secrets.get("hub.token")).flatMap { String(data: $0, encoding: .utf8) }
        adapters = Self.loadPins(defaults)
        user = defaults.string(forKey: "user")
        account = defaults.string(forKey: "account")
    }

    var isEnrolled: Bool { hubURL != nil && token != nil && keys.hasKeys() }
    var isInsecure: Bool { keys.kind == .software }
    /// Only a current member of its user's roster may approve: adapters seal requests to roster members only, and a
    /// removed device must not act on anything it still holds.
    var canApprove: Bool { membership == .member }
    var deviceFingerprint: String? { (try? keys.publicKeys()).map { Fingerprint.of($0.approve) } }
    var deviceID: String? { try? device.deviceID() }

    /// The last head accepted (seq + payload hash), persisted: refuses rollbacks and forks across restarts.
    private var knownHead: KnownHead? {
        get { defaults.data(forKey: "knownHead").flatMap { try? JSONDecoder().decode(KnownHead.self, from: $0) } }
        set { defaults.set(newValue.flatMap { try? JSONEncoder().encode($0) }, forKey: "knownHead") }
    }

    private var client: HubClient? {
        guard let hubURL else { return nil }
        return HubClient(base: hubURL, token: token)
    }

    private var pins: [String: Data] { Dictionary(uniqueKeysWithValues: adapters.map { ($0.id, $0.key) }) }

    // MARK: enrollment

    /// mode new: this device creates the user's first roster (r1) and pins its account fingerprint.
    /// mode join: this device asks to join; it is pending until a device of the user signs a roster that includes it.
    func enroll(_ link: EnrollmentLink, name: String, pin: String?) async {
        lastError = nil
        do {
            let keys = self.keys
            let user = link.user
            let mode = link.mode
            // Signing uses the approve key: Face ID / PIN on a device (for a new user twice: card, then r1).
            let (card, genesis): (Envelope, Envelope?) = try await Task.detached {
                if !keys.hasKeys() { try keys.generate(pin: pin) }
                let dev = Device(keys: keys)
                let card = try dev.card(name: name, pin: pin)
                return (card, mode == .new ? try dev.genesis(user: user, card: card, pin: pin) : nil)
            }.value
            let resp = try await HubClient(base: link.hub, token: nil).enroll(code: link.code, card: card, genesis: genesis)
            let ours = try device.deviceID()
            guard resp.deviceId == ours else {
                throw ProtocolError.mismatch("hub enrolled \(resp.deviceId), this device is \(ours)")
            }
            if let u = resp.user, u != user { throw ProtocolError.mismatch("hub enrolled this device for \(u), not \(user)") }
            // Only now, with the new hub's token in hand, forget the old hub (and the account, if it changes, or if
            // this is a new account). Adapter pins are per hub; keys are kept.
            if hubURL != link.hub || self.user != user || genesis != nil { forgetHub() }
            try secrets.set("hub.token", Data(resp.token.utf8))
            defaults.set(link.hub, forKey: "hubURL")
            hubURL = link.hub
            token = resp.token
            self.user = user
            defaults.set(user, forKey: "user")
            if let genesis {
                setAccount(accountFingerprint(genesisPayload: try B64.decode(genesis.payload)))
            }
            await refreshAdapters()
            await refreshRoster()
            pendingLink = nil
            sheet = .summary(EnrollmentSummary(deviceFingerprint: Fingerprint.of(try keys.publicKeys().approve),
                                               adapters: adapters, user: user, account: account))
        } catch {
            lastError = error.localizedDescription
        }
    }

    private func setAccount(_ a: String?) {
        account = a
        defaults.set(a, forKey: "account")
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

    // MARK: roster

    /// Fetches the user's chain, verifies it against the pinned account, and accepts it only if it builds on the head
    /// already accepted (no rollback, no fork). On failure the last good head stays and the error is shown.
    func refreshRoster() async {
        guard let client, let user else { return }
        do {
            let r = try await client.roster()
            guard r.user == user else { throw ProtocolError.mismatch("hub sent the roster of \(r.user)") }
            let h = try verifyChain(r.chain, user: user, account: account)
            let me = try device.deviceID()
            let inHead = h.devices[me] != nil
            if account == nil {
                guard inHead else {
                    // Not a member yet: show the hub's account fingerprint for comparison, pin nothing.
                    unconfirmedAccount = h.account
                    membership = .pending
                    rosterError = nil
                    return
                }
                setAccount(h.account) // first verified chain that includes this device
                unconfirmedAccount = nil
            }
            try requireBuildsOn(r.chain, known: knownHead)
            head = h
            knownHead = KnownHead(h)
            if inHead {
                membership = .member
                defaults.set(true, forKey: "wasMember")
            } else {
                membership = defaults.bool(forKey: "wasMember") ? .removed : .pending
            }
            rosterError = nil
        } catch HubClient.HubError.http(404, _) {
            membership = .pending // the hub has no roster for this user yet
        } catch HubClient.HubError.http(401, _) {
            // refresh() reports the 401
        } catch {
            rosterError = "Roster refused: \(error.localizedDescription)"
        }
    }

    func refreshJoins() async {
        guard let client, membership == .member else { joins = []; return }
        if let j = try? await client.joins() { joins = j }
    }

    /// Admits a device asking to join: next roster = verified head + its card, signed here (Face ID).
    func approveJoin(_ join: HubJoin, pin: String? = nil) async throws {
        try await changeRoster { dev, head in
            let card = try verifyCard(join.card)
            guard card.deviceId == join.deviceId else { throw ProtocolError.mismatch("join card is for another device") }
            guard head.devices[card.deviceId] == nil else { throw ProtocolError.mismatch("already a member") }
            return try dev.admit(join.card, after: head, pin: pin)
        }
        joins.removeAll { $0.deviceId == join.deviceId }
    }

    /// Removes a device: next roster = verified head without it, signed here (Face ID).
    func removeDevice(_ id: String, pin: String? = nil) async throws {
        try await changeRoster { dev, head in try dev.remove(id, after: head, pin: pin) }
    }

    /// Builds the next roster from this device's own freshly verified copy of the chain, never from the hub's say-so.
    private func changeRoster(_ build: @escaping @Sendable (Device, Head) throws -> Envelope) async throws {
        guard let client, let user, let account else { throw ProtocolError.untrusted("no pinned account") }
        let r = try await client.roster()
        let h = try verifyChain(r.chain, user: user, account: account)
        try requireBuildsOn(r.chain, known: knownHead)
        guard h.devices[try device.deviceID()] != nil else { throw ProtocolError.untrusted("this device is not a member") }
        let keys = self.keys
        let env = try await Task.detached { try build(Device(keys: keys), h) }.value
        _ = try extend(h, env) // check our own work before sending it
        try await client.postRoster(env)
        await refreshRoster()
    }

    // MARK: inbox

    func refresh() async {
        guard isEnrolled, let client else { return }
        await refreshRoster()
        await refreshJoins()
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
                + "Get a new enrollment code, then Device → Connect to another server (the same server works too)."
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
        guard canApprove else {
            outcomes[req.id] = .failed("this device is not a member of \(user ?? "its account")")
            return
        }
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

    /// Leaves the hub: token, hub URL, pins, account and everything seen through it. The device keys stay.
    func leaveHub() {
        forgetHub()
        lastError = nil
    }

    /// Leaves the hub and deletes the device keys.
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
        user = nil
        setAccount(nil)
        unconfirmedAccount = nil
        head = nil
        membership = .unknown
        joins = []
        rosterError = nil
        defaults.removeObject(forKey: "user")
        defaults.removeObject(forKey: "knownHead")
        defaults.removeObject(forKey: "wasMember")
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
