import CryptoKit
import Foundation

/// A record that opened, verified against the pinned adapter key, and matched the hub's listing.
public struct OpenedRequest: Identifiable, Equatable, Sendable {
    public var id: String { "\(record.adapter)/\(record.id)" }
    public var record: Record
    /// The exact signed payload bytes: the decision's record_hash covers these.
    public var payload: Data
}

/// The device's half of the protocol, on top of a key store. Verify first, then parse.
public struct Device: Sendable {
    public let keys: KeyStore

    public init(keys: KeyStore) { self.keys = keys }

    public func deviceID() throws -> String { try keys.publicKeys().deviceID }

    // MARK: card

    /// The signed device card for enrollment. Signing uses the approve key, so it asks for Face ID / the PIN.
    public func card(name: String, now: Date = Date(), pin: String? = nil) throws -> Envelope {
        let pk = try keys.publicKeys()
        let card = DeviceCard(v: protocolVersion, deviceId: pk.deviceID, name: name,
                              approveKey: B64.encode(pk.approve), denyKey: B64.encode(pk.deny), encKey: B64.encode(pk.enc),
                              createdAt: Int64(now.timeIntervalSince1970))
        let payload = try Coders.encoder.encode(card)
        return Envelope(alg: Envelope.es256, kid: pk.deviceID, payload: B64.encode(payload),
                        sig: B64.encode(try keys.signApprove(payload, pin: pin)))
    }

    // MARK: records

    /// Opens a box from the hub and checks every rule in PROTOCOL.md before anything is shown.
    /// `pinned`: adapter id -> raw Ed25519 public key.
    public func open(_ listing: HubRequest, pinned: [String: Data]) throws -> OpenedRequest {
        let box = listing.box
        guard box.suite == Sealed.suiteHPKE else { throw ProtocolError.malformed("unknown suite \(box.suite)") }
        guard box.kid == (try deviceID()) else { throw ProtocolError.mismatch("box is addressed to another device") }
        let plaintext: Data
        do {
            plaintext = try keys.open(enc: B64.decode(box.enc), ciphertext: B64.decode(box.ct), info: recordInfo)
        } catch {
            throw ProtocolError.badSignature("box does not open")
        }
        let env = try Coders.decoder.decode(Envelope.self, from: plaintext)
        guard env.alg == Envelope.ed25519 else { throw ProtocolError.malformed("record alg \(env.alg)") }
        guard env.kid == listing.adapter else { throw ProtocolError.mismatch("record signer differs from the hub's listing") }
        let payload = try verifyEd25519(env, pinned: pinned)
        let rec = try Coders.decoder.decode(Record.self, from: payload)
        guard rec.v == protocolVersion else { throw ProtocolError.malformed("record version \(rec.v)") }
        guard rec.adapter == env.kid else { throw ProtocolError.mismatch("record names another adapter than its signer") }
        guard rec.id == listing.id, rec.adapter == listing.adapter else {
            throw ProtocolError.mismatch("record differs from the hub's listing")
        }
        return OpenedRequest(record: rec, payload: payload)
    }

    // MARK: decisions

    /// Signs a decision: approve with the approve key (Face ID / PIN), deny with the deny key.
    public func decide(_ req: OpenedRequest, approve: Bool, now: Date = Date(), pin: String? = nil) throws -> Envelope {
        let id = try deviceID()
        let d = Decision(v: protocolVersion, requestId: req.record.id, adapter: req.record.adapter,
                         decision: approve ? Decision.approve : Decision.deny, recordHash: B64.encode(sha256(req.payload)),
                         nonce: req.record.nonce, deviceId: id, ts: Int64(now.timeIntervalSince1970))
        let payload = try Coders.encoder.encode(d)
        let sig = approve ? try keys.signApprove(payload, pin: pin) : try keys.signDeny(payload)
        return Envelope(alg: Envelope.es256, kid: id, payload: B64.encode(payload), sig: B64.encode(sig))
    }

    // MARK: acks

    /// Verifies an adapter's acknowledgement. `decision` (if known) must be the one it acknowledges.
    public func verifyAck(_ hubAck: HubAck, pinned: [String: Data], decision: Envelope? = nil) throws -> Ack {
        let env = hubAck.ack
        guard env.alg == Envelope.ed25519, env.kid == hubAck.adapter else { throw ProtocolError.mismatch("ack signer") }
        let payload = try verifyEd25519(env, pinned: pinned)
        let ack = try Coders.decoder.decode(Ack.self, from: payload)
        guard ack.adapter == env.kid, ack.requestId == hubAck.requestId else {
            throw ProtocolError.mismatch("ack differs from the hub's listing")
        }
        if let decision, let dh = ack.decisionHash, !dh.isEmpty {
            guard dh == B64.encode(sha256(try B64.decode(decision.payload))) else {
                throw ProtocolError.mismatch("ack is for a different decision")
            }
        }
        return ack
    }

    private func verifyEd25519(_ env: Envelope, pinned: [String: Data]) throws -> Data {
        guard let raw = pinned[env.kid] else { throw ProtocolError.untrusted("adapter \(env.kid) is not pinned") }
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: raw)
        let payload = try B64.decode(env.payload)
        guard key.isValidSignature(try B64.decode(env.sig), for: payload) else {
            throw ProtocolError.badSignature("adapter \(env.kid)")
        }
        return payload
    }
}

/// Verifies an ES256 envelope against an X9.63 P-256 key (used to check cards).
public func verifyES256(_ env: Envelope, x963: Data) throws -> Data {
    guard env.alg == Envelope.es256 else { throw ProtocolError.malformed("alg \(env.alg)") }
    let key = try P256.Signing.PublicKey(x963Representation: x963)
    let payload = try B64.decode(env.payload)
    let sig = try P256.Signing.ECDSASignature(rawRepresentation: B64.decode(env.sig))
    guard key.isValidSignature(sig, for: payload) else { throw ProtocolError.badSignature("es256") }
    return payload
}

/// `wga://enroll?hub=<url>&code=<code>&user=<id>&mode=new|join`
public struct EnrollmentLink: Equatable, Sendable {
    public enum Mode: String, Sendable { case new, join }

    public var hub: URL
    public var code: String
    public var user: String
    public var mode: Mode

    public enum LinkError: Error, LocalizedError, Equatable {
        case notALink
        case old
        public var errorDescription: String? {
            switch self {
            case .notALink: return "Not an enrollment link."
            case .old: return "Old enrollment link (no user or mode): ask for a new code."
            }
        }
    }

    public init?(_ s: String) { try? self.init(parsing: s) }

    public init(parsing s: String) throws {
        guard let c = URLComponents(string: s.trimmingCharacters(in: .whitespacesAndNewlines)),
              c.scheme == "wga", c.host == "enroll",
              let hubS = c.queryItems?.first(where: { $0.name == "hub" })?.value,
              let hub = URL(string: hubS), let scheme = hub.scheme, ["http", "https"].contains(scheme),
              let code = c.queryItems?.first(where: { $0.name == "code" })?.value, !code.isEmpty
        else { throw LinkError.notALink }
        guard let user = c.queryItems?.first(where: { $0.name == "user" })?.value, isValidUserID(user),
              let m = c.queryItems?.first(where: { $0.name == "mode" })?.value, let mode = Mode(rawValue: m)
        else { throw LinkError.old }
        self.hub = hub
        self.code = code
        self.user = user
        self.mode = mode
    }
}

/// Makes requester-written text safe to show: no control or format characters (bidi overrides, zero-width), one line.
public func sanitize(_ s: String) -> String {
    var out = String.UnicodeScalarView()
    for u in s.unicodeScalars {
        switch u {
        case "\n", "\r", "\t":
            out.append(" ")
        default:
            switch u.properties.generalCategory {
            case .control, .format: continue
            default: out.append(u)
            }
        }
    }
    return String(out).split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
}
