import Foundation

// Wire types of docs/PROTOCOL.md v1. Property names map to snake_case JSON (requestId <-> request_id).

public let protocolVersion = 1

public struct Envelope: Codable, Equatable, Sendable {
    public var alg: String
    public var kid: String
    public var payload: String
    public var sig: String

    public static let ed25519 = "ed25519"
    public static let es256 = "es256"
}

public struct Sealed: Codable, Equatable, Sendable {
    public var suite: String
    public var kid: String
    public var enc: String
    public var ct: String

    public static let suiteHPKE = "hpke-p256-sha256-aes256gcm"
}

public struct Fact: Codable, Equatable, Sendable, Hashable {
    public var label: String
    public var value: String
    /// "", "warn" or "danger"
    public var level: String?
}

public struct Principal: Codable, Equatable, Sendable {
    public var principal: String
    public var display: String?
    public var attestedBy: String
}

public struct Lease: Codable, Equatable, Sendable {
    public var durationS: Int64
    public var scope: String
    public var maxUses: Int?
}

public struct Record: Codable, Equatable, Sendable {
    public var v: Int
    public var id: String
    public var adapter: String
    public var kind: String
    public var shape: String
    public var risk: String
    public var title: String
    public var requester: String
    public var onBehalfOf: Principal?
    public var facts: [Fact]?
    public var reason: String?
    public var lease: Lease?
    public var createdAt: Int64
    public var expiresAt: Int64
    public var nonce: String

    public var isHighRisk: Bool { risk == "high" }
    public func isExpired(at now: Date = Date()) -> Bool { Int64(now.timeIntervalSince1970) > expiresAt }
}

public struct Decision: Codable, Equatable, Sendable {
    public var v: Int
    public var requestId: String
    public var adapter: String
    public var decision: String
    public var recordHash: String
    public var nonce: String
    public var deviceId: String
    public var ts: Int64

    public static let approve = "approve"
    public static let deny = "deny"
}

public struct Ack: Codable, Equatable, Sendable {
    public var v: Int
    public var requestId: String
    public var adapter: String
    /// approved, denied, expired: final. rejected, failed: notes; the request stays pending and can be decided again.
    public var outcome: String
    public var detail: String?
    public var decisionHash: String?
    public var ts: Int64

    public var isFinal: Bool { ["approved", "denied", "expired"].contains(outcome) }
}

public struct DeviceCard: Codable, Equatable, Sendable {
    public var v: Int
    public var deviceId: String
    public var name: String
    public var approveKey: String
    public var denyKey: String
    public var encKey: String
    public var createdAt: Int64
}

// MARK: hub API shapes

public struct EnrollRequest: Codable, Sendable {
    public var code: String
    public var card: Envelope
    /// r1 of a new user (mode new); absent for a join.
    public var genesis: Envelope?
}

public struct EnrollResponse: Codable, Sendable {
    public var deviceId: String
    public var token: String
    public var user: String?
    /// "active" (in the head roster) or "pending" (join not approved yet).
    public var status: String?
}

public struct HubRoster: Codable, Equatable, Sendable {
    public var user: String
    public var chain: [Envelope]
}

public struct HubJoin: Codable, Equatable, Sendable, Identifiable {
    public var deviceId: String
    public var name: String
    public var card: Envelope
    public var requestedAt: Int64? // Unix seconds, as the hub sends it
    public var id: String { deviceId }
}

public struct RosterPost: Codable, Sendable {
    public var roster: Envelope
}

/// POST /v1/device/leave: the device goes away from the hub. `roster` takes it off the account first (signed by it);
/// `deleteAccount` is for the account's last device; neither leaves the roster as it is.
public struct LeavePost: Codable, Sendable {
    public var roster: Envelope?
    public var deleteAccount: Bool?

    public init(roster: Envelope? = nil, deleteAccount: Bool = false) {
        self.roster = roster
        self.deleteAccount = deleteAccount ? true : nil
    }
}

public struct HubAdapter: Codable, Equatable, Sendable, Identifiable {
    public var id: String
    public var key: String
    public var fingerprint: String
}

public struct HubRequest: Codable, Equatable, Sendable {
    public var id: String
    public var adapter: String
    public var kind: String
    public var createdAt: Int64
    public var expiresAt: Int64
    public var box: Sealed
}

public struct DecisionPost: Codable, Sendable {
    public var adapter: String
    public var requestId: String
    public var decision: Envelope

    public init(adapter: String, requestId: String, decision: Envelope) {
        self.adapter = adapter
        self.requestId = requestId
        self.decision = decision
    }
}

public struct HubAck: Codable, Equatable, Sendable {
    public var adapter: String
    public var requestId: String
    public var ack: Envelope
}
