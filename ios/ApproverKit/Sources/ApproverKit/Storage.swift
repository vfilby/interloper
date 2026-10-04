import Foundation
import Security

/// Where small secrets live: the Keychain on a device, memory in tests.
public protocol SecretStorage: Sendable {
    func get(_ key: String) throws -> Data?
    func set(_ key: String, _ value: Data) throws
    func delete(_ key: String) throws
}

public struct KeychainError: Error, LocalizedError {
    public let status: OSStatus
    public var errorDescription: String? { "Keychain error \(status)" }
}

/// Generic-password items, this device only, available after first unlock.
public struct KeychainStorage: SecretStorage {
    public let service: String

    public init(service: String = "com.eff3.interloper") { self.service = service }

    private func query(_ key: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: key]
    }

    public func get(_ key: String) throws -> Data? {
        var q = query(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound { return nil }
        guard st == errSecSuccess else { throw KeychainError(status: st) }
        return out as? Data
    }

    public func set(_ key: String, _ value: Data) throws {
        try delete(key)
        var q = query(key)
        q[kSecValueData as String] = value
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let st = SecItemAdd(q as CFDictionary, nil)
        guard st == errSecSuccess else { throw KeychainError(status: st) }
    }

    public func delete(_ key: String) throws {
        let st = SecItemDelete(query(key) as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else { throw KeychainError(status: st) }
    }
}

public final class MemoryStorage: SecretStorage, @unchecked Sendable {
    private var items: [String: Data] = [:]
    private let lock = NSLock()

    public init() {}

    public func get(_ key: String) throws -> Data? { lock.withLock { items[key] } }
    public func set(_ key: String, _ value: Data) throws { lock.withLock { items[key] = value } }
    public func delete(_ key: String) throws { _ = lock.withLock { items.removeValue(forKey: key) } }
}
