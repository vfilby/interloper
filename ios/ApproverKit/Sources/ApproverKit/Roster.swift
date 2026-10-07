import CryptoKit
import Foundation

// Users and rosters (docs/PROTOCOL.md "Users and rosters"). Mirrors broker/internal/protocol/roster.go rule for rule.

public struct Member: Codable, Equatable, Sendable {
    public var kind: String
    public var card: Envelope

    public static let device = "device"

    public init(kind: String = Member.device, card: Envelope) {
        self.kind = kind
        self.card = card
    }
}

public struct Roster: Codable, Equatable, Sendable {
    public var t: String = PayloadType.roster
    public var v: Int
    public var user: String
    public var seq: Int
    public var prev: String
    public var members: [Member]
    public var ts: Int64
}

/// The newest roster of a verified chain, with its devices.
public struct Head: Equatable, Sendable {
    public var roster: Roster
    /// Exact bytes of the head roster: the next roster's prev hashes these.
    public var payload: Data
    public var devices: [String: DeviceCard]
    /// Account fingerprint (from r1).
    public var account: String

    /// Member card envelopes, in roster order.
    public var cards: [Envelope] { roster.members.map(\.card) }
}

/// First 16 bytes of SHA-256 over the genesis payload, as 8 groups of 4 hex digits.
public func accountFingerprint(genesisPayload: Data) -> String {
    let h = sha256(genesisPayload).prefix(16).map { String(format: "%02x", $0) }.joined()
    return stride(from: 0, to: h.count, by: 4).map { i -> String in
        let a = h.index(h.startIndex, offsetBy: i)
        return String(h[a..<h.index(a, offsetBy: 4)])
    }.joined(separator: "-")
}

/// 1-40 of a-z 0-9 . _ -
public func isValidUserID(_ s: String) -> Bool {
    guard (1...40).contains(s.count) else { return false }
    return s.unicodeScalars.allSatisfy { c in
        ("a"..."z").contains(c) || ("0"..."9").contains(c) || c == "." || c == "_" || c == "-"
    }
}

/// Mirrors Go's VerifyCard: self-signed by the approve key, typed a card, id = fingerprint of that key, a valid name,
/// all keys parse.
public func verifyCard(_ env: Envelope) throws -> DeviceCard {
    let payload = try B64.decode(env.payload)
    let card = try Coders.decoder.decode(DeviceCard.self, from: payload)
    let ak = try B64.decode(card.approveKey)
    _ = try verifyES256(env, x963: ak)
    guard card.t == PayloadType.card else { throw ProtocolError.malformed("card: payload is a \(card.t), not a card") }
    guard isValidDeviceName(card.name) else {
        throw ProtocolError.malformed("card: device name longer than \(maxDeviceName) bytes or with control or format characters")
    }
    guard card.v == protocolVersion, card.deviceId == Fingerprint.deviceID(approveKey: ak), env.kid == card.deviceId else {
        throw ProtocolError.mismatch("card: version, device id and approve key do not match")
    }
    _ = try P256.Signing.PublicKey(x963Representation: B64.decode(card.denyKey))
    _ = try P256.KeyAgreement.PublicKey(x963Representation: B64.decode(card.encKey))
    return card
}

private func parseRoster(_ payload: Data) throws -> (Roster, [String: DeviceCard]) {
    let r: Roster
    do { r = try Coders.decoder.decode(Roster.self, from: payload) } catch {
        throw ProtocolError.malformed("roster: \(error.localizedDescription)")
    }
    guard r.t == PayloadType.roster else { throw ProtocolError.malformed("roster: payload is a \(r.t), not a roster") }
    guard r.v == protocolVersion, isValidUserID(r.user), r.seq >= 1, !r.members.isEmpty else {
        throw ProtocolError.malformed("roster: bad version, user, seq or empty members")
    }
    var devs: [String: DeviceCard] = [:]
    for m in r.members {
        guard m.kind == Member.device else { throw ProtocolError.malformed("roster: unknown member kind \(m.kind)") }
        let c: DeviceCard
        do { c = try verifyCard(m.card) } catch {
            throw ProtocolError.badSignature("roster member card: \(error.localizedDescription)")
        }
        guard devs[c.deviceId] == nil else { throw ProtocolError.malformed("roster: device \(c.deviceId) listed twice") }
        devs[c.deviceId] = c
    }
    return (r, devs)
}

/// Checks that env is signed by the approve key of one of devs.
private func signed(_ env: Envelope, by devs: [String: DeviceCard]) throws -> Data {
    guard let c = devs[env.kid] else {
        throw ProtocolError.untrusted("roster signed by \(env.kid), which is not a member of the roster it must be signed under")
    }
    return try verifyES256(env, x963: B64.decode(c.approveKey))
}

/// Finds and verifies the card of the member that claims to have signed a genesis roster.
private func genesisSigner(_ env: Envelope) throws -> [String: DeviceCard] {
    struct Members: Decodable { var members: [Member] }
    let m: Members
    do { m = try Coders.decoder.decode(Members.self, from: B64.decode(env.payload)) } catch {
        throw ProtocolError.malformed("roster: \(error.localizedDescription)")
    }
    guard let mine = m.members.first(where: { $0.kind == Member.device && $0.card.kid == env.kid }) else {
        throw ProtocolError.untrusted("roster signed by \(env.kid), which is not a member of the roster it must be signed under")
    }
    let c: DeviceCard
    do { c = try verifyCard(mine.card) } catch {
        throw ProtocolError.badSignature("roster member card: \(error.localizedDescription)")
    }
    return [c.deviceId: c]
}

/// Verifies a whole chain for `user`; `account` nil skips the pin (first sight, which then pins what it saw).
public func verifyChain(_ chain: [Envelope], user: String, account: String?) throws -> Head {
    guard let first = chain.first else { throw ProtocolError.malformed("empty roster chain") }
    // Only the signer's card is verified before the genesis signature (it holds the key that signature is checked
    // with); the other cards after, as extend does.
    let gp = try signed(first, by: genesisSigner(first))
    let (r, devs) = try parseRoster(gp)
    guard r.seq == 1, r.prev.isEmpty, r.user == user else {
        throw ProtocolError.mismatch("genesis: must be seq 1, no prev, and for this user")
    }
    let acct = accountFingerprint(genesisPayload: gp)
    if let account, acct != account {
        throw ProtocolError.mismatch("account fingerprint \(acct) does not match the pinned \(account)")
    }
    var head = Head(roster: r, payload: gp, devices: devs, account: acct)
    for env in chain.dropFirst() { head = try extend(head, env) }
    return head
}

/// Checks that env is the roster after head (signed by a member of head) and returns the new head.
public func extend(_ head: Head, _ env: Envelope) throws -> Head {
    let p = try signed(env, by: head.devices)
    let (r, devs) = try parseRoster(p)
    guard r.user == head.roster.user else { throw ProtocolError.mismatch("roster changes user") }
    guard r.seq == head.roster.seq + 1 else { throw ProtocolError.mismatch("roster seq \(r.seq) after \(head.roster.seq)") }
    guard r.prev == B64.encode(sha256(head.payload)) else {
        throw ProtocolError.mismatch("roster \(r.seq) does not follow roster \(head.roster.seq)")
    }
    return Head(roster: r, payload: p, devices: devs, account: head.account)
}

/// What a device remembers of the last head it accepted: enough to refuse rollbacks and forks after a restart.
public struct KnownHead: Codable, Equatable, Sendable {
    public var seq: Int
    /// b64url SHA-256 of that roster's payload bytes.
    public var payloadHash: String

    public init(seq: Int, payloadHash: String) {
        self.seq = seq
        self.payloadHash = payloadHash
    }

    public init(_ head: Head) {
        self.init(seq: head.roster.seq, payloadHash: B64.encode(sha256(head.payload)))
    }
}

/// A verified chain must build on the head already accepted: not shorter (rollback), and holding exactly that
/// roster at its seq. Otherwise a device removed at vN, which still has its key, could sign an alternative vN' from
/// v(N-1) and then vN+1': that verifies from genesis and is longer, and would undo the removal.
public func requireBuildsOn(_ chain: [Envelope], known: KnownHead?) throws {
    guard let known, known.seq > 0 else { return }
    guard chain.count >= known.seq else {
        throw ProtocolError.mismatch("hub offered roster \(chain.count), older than \(known.seq) already seen")
    }
    guard B64.encode(sha256(try B64.decode(chain[known.seq - 1].payload))) == known.payloadHash else {
        throw ProtocolError.mismatch("roster chain does not build on the roster already seen (\(known.seq))")
    }
}

/// The (unsigned) roster after head with the given member cards.
public func nextRoster(after head: Head, members: [Envelope], now: Date = Date()) -> Roster {
    Roster(v: protocolVersion, user: head.roster.user, seq: head.roster.seq + 1, prev: B64.encode(sha256(head.payload)),
           members: members.map { Member(card: $0) }, ts: Int64(now.timeIntervalSince1970))
}

extension Device {
    /// Signs a roster with the approve key (Face ID / PIN on a device).
    public func sign(_ roster: Roster, pin: String? = nil) throws -> Envelope {
        let id = try deviceID()
        let payload = try Coders.encoder.encode(roster)
        return Envelope(alg: Envelope.es256, kid: id, payload: B64.encode(payload), sig: B64.encode(try keys.signApprove(payload, pin: pin)))
    }

    /// r1 of a new user: this device, alone.
    public func genesis(user: String, card: Envelope, now: Date = Date(), pin: String? = nil) throws -> Envelope {
        try sign(Roster(v: protocolVersion, user: user, seq: 1, prev: "", members: [Member(card: card)],
                        ts: Int64(now.timeIntervalSince1970)), pin: pin)
    }

    /// The roster after head with card added (approving a join).
    public func admit(_ card: Envelope, after head: Head, now: Date = Date(), pin: String? = nil) throws -> Envelope {
        try sign(nextRoster(after: head, members: head.cards + [card], now: now), pin: pin)
    }

    /// The roster after head without deviceID.
    public func remove(_ deviceID: String, after head: Head, now: Date = Date(), pin: String? = nil) throws -> Envelope {
        let keep = head.cards.filter { $0.kid != deviceID }
        guard !keep.isEmpty else { throw ProtocolError.malformed("cannot remove the last device of an account") }
        return try sign(nextRoster(after: head, members: keep, now: now), pin: pin)
    }
}
