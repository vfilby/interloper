import Foundation

/// An adapter's request-signing key, pinned once the person confirmed its fingerprint.
public struct PinnedAdapter: Identifiable, Equatable, Codable, Sendable {
    public var id: String
    public var key: Data
    public var fingerprint: String { Fingerprint.of(key) }

    public init(id: String, key: Data) {
        self.id = id
        self.key = key
    }
}

/// A hub claim that disagrees with a pin: never used, always shown.
public struct AdapterConflict: Identifiable, Equatable, Sendable {
    public var id: String
    public var pinned: String
    public var offered: String

    public init(id: String, pinned: String, offered: String) {
        self.id = id
        self.pinned = pinned
        self.offered = offered
    }
}

/// Sorts the hub's adapter list against the pins. A key for an id not pinned yet is only offered: the hub could have
/// minted it, so it is used once the person compared its fingerprint with the one the adapter prints. A different key
/// for a pinned id is a conflict. Keys that are not 32 bytes are dropped.
public func sortAdapters(_ listed: [HubAdapter], pinned: [PinnedAdapter]) -> (offered: [PinnedAdapter], conflicts: [AdapterConflict]) {
    var offered: [PinnedAdapter] = []
    var conflicts: [AdapterConflict] = []
    for a in listed {
        guard let key = try? B64.decode(a.key), key.count == 32 else { continue }
        if let p = pinned.first(where: { $0.id == a.id }) {
            if p.key != key { conflicts.append(AdapterConflict(id: a.id, pinned: p.fingerprint, offered: Fingerprint.of(key))) }
        } else if !offered.contains(where: { $0.id == a.id }) {
            offered.append(PinnedAdapter(id: a.id, key: key))
        }
    }
    return (offered.sorted { $0.id < $1.id }, conflicts)
}

/// What this device pins, in the Keychain (this device only, so a backup restored elsewhere or edited cannot carry or
/// change them): the account fingerprint, adapter keys, the last accepted roster head, and an account fingerprint the
/// person said does not match.
public struct PinStore: Sendable {
    public enum Key: String, CaseIterable, Sendable {
        case account = "pin.account"
        case adapters = "pin.adapters"
        case knownHead = "pin.knownHead"
        case rejectedAccount = "pin.rejectedAccount"
    }

    public let storage: SecretStorage

    public init(storage: SecretStorage) { self.storage = storage }

    public func load<T: Decodable>(_ key: Key, as: T.Type = T.self) throws -> T? {
        try storage.get(key.rawValue).map { try JSONDecoder().decode(T.self, from: $0) }
    }

    /// nil deletes.
    public func save<T: Encodable>(_ key: Key, _ value: T?) throws {
        if let value {
            try storage.set(key.rawValue, try JSONEncoder().encode(value))
        } else {
            try storage.delete(key.rawValue)
        }
    }

    public func clear() throws {
        for k in Key.allCases { try storage.delete(k.rawValue) }
    }

    /// Earlier versions kept the pins in UserDefaults ("account", "pinnedAdapters" as id → b64url key, "knownHead"):
    /// moves them here, unless a pin is already here, and removes them there.
    public func migrate(from d: UserDefaults) throws {
        if let a = d.string(forKey: "account") {
            if try storage.get(Key.account.rawValue) == nil { try save(.account, a) }
            d.removeObject(forKey: "account")
        }
        if let m = d.dictionary(forKey: "pinnedAdapters") as? [String: String] {
            if try storage.get(Key.adapters.rawValue) == nil {
                let pins = m.compactMap { id, k in (try? B64.decode(k)).map { PinnedAdapter(id: id, key: $0) } }
                try save(.adapters, pins.sorted { $0.id < $1.id })
            }
            d.removeObject(forKey: "pinnedAdapters")
        }
        if let h = d.data(forKey: "knownHead") {
            if try storage.get(Key.knownHead.rawValue) == nil, let k = try? JSONDecoder().decode(KnownHead.self, from: h) {
                try save(.knownHead, k)
            }
            d.removeObject(forKey: "knownHead")
        }
    }
}
