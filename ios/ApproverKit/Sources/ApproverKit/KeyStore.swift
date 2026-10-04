import CryptoKit
import CryptoTokenKit
import Foundation
import LocalAuthentication

/// What the approve key's refusals mean to a person.
public enum ApproveKeyError: Error, LocalizedError {
    case wrongPIN

    public var errorDescription: String? {
        switch self {
        case .wrongPIN: "Wrong app PIN. It is the PIN set when this device was connected, not the phone's passcode."
        }
    }
}

/// The device's three keys (docs/PROTOCOL.md "Keys"). Private keys never leave the store; callers get public keys,
/// signatures and decrypted boxes.
public protocol KeyStore: Sendable {
    var kind: KeyStoreKind { get }
    func hasKeys() -> Bool
    /// Creates all three keys. `pin` is the app PIN bound into the Secure Enclave approve key as its alternative to
    /// Face ID; the software store ignores it.
    func generate(pin: String?) throws
    func publicKeys() throws -> DevicePublicKeys
    /// Signs with the approve key: on a device this is the Face ID (or app PIN) prompt. Raw r||s, 64 bytes.
    func signApprove(_ data: Data, pin: String?) throws -> Data
    /// Signs with the deny key: needs only an unlocked device.
    func signDeny(_ data: Data) throws -> Data
    /// HPKE open (P256_SHA256_AES_GCM_256) with the encryption key.
    func open(enc: Data, ciphertext: Data, info: Data) throws -> Data
    func reset() throws
}

public enum KeyStoreKind: String, Sendable {
    case secureEnclave = "Secure Enclave"
    case software = "Software (INSECURE, testing only)"
}

public struct DevicePublicKeys: Equatable, Sendable {
    public var approve: Data
    public var deny: Data
    public var enc: Data

    public var deviceID: String { Fingerprint.deviceID(approveKey: approve) }
}

public let recordInfo = Data("wga/v1/record".utf8)

/// Picks the Secure Enclave when there is one. The simulator always gets software keys: it reports a Secure Enclave,
/// but Face ID / app-password access control there is not the real thing.
public func defaultKeyStore() -> KeyStore {
    #if targetEnvironment(simulator)
    return SoftwareKeyStore(storage: KeychainStorage())
    #else
    return SecureEnclave.isAvailable ? SecureEnclaveKeyStore(storage: KeychainStorage()) : SoftwareKeyStore(storage: KeychainStorage())
    #endif
}

// MARK: - Secure Enclave

public final class SecureEnclaveKeyStore: KeyStore, @unchecked Sendable {
    private let storage: SecretStorage
    public let kind = KeyStoreKind.secureEnclave

    public init(storage: SecretStorage) { self.storage = storage }

    public func hasKeys() -> Bool {
        ["approve", "deny", "enc"].allSatisfy { (try? storage.get(Self.slot($0))) != nil }
    }

    private static func slot(_ name: String) -> String { "se.\(name)" }

    // Approve: Face ID (current enrollment) or the app PIN, never just the device passcode. iOS cannot express that on
    // one key: with .applicationPassword in its access control, a Secure Enclave key asks for the password even after
    // Face ID succeeds, `.or` or not. So the key needs only the app PIN, and a copy of the PIN is kept in a keychain
    // item that only Face ID (current enrollment) opens: Face ID reads the PIN and the PIN opens the key, one prompt.
    // If Face ID fails or is cancelled, iOS asks for the PIN itself. The cost: the PIN passes through app memory.
    // Keys made before this (Face ID and PIN in one access control) still need both; the stored PIN supplies the
    // second, once the person has approved with the PIN typed in the app.

    public func generate(pin: String?) throws {
        guard let pin, !pin.isEmpty else { throw ProtocolError.malformed("the Secure Enclave approve key needs an app PIN") }
        var err: Unmanaged<CFError>?
        guard let approveAC = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                              [.privateKeyUsage, .applicationPassword], &err),
              let denyAC = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &err),
              let encAC = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage], &err)
        else { throw err!.takeRetainedValue() as Error }

        let ctx = LAContext()
        ctx.setCredential(Data(pin.utf8), type: .applicationPassword)
        let approve = try SecureEnclave.P256.Signing.PrivateKey(accessControl: approveAC, authenticationContext: ctx)
        let deny = try SecureEnclave.P256.Signing.PrivateKey(accessControl: denyAC)
        let enc = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: encAC)
        // dataRepresentation is an opaque handle only this device's Secure Enclave can use.
        try storage.set(Self.slot("approve"), approve.dataRepresentation)
        try storage.set(Self.slot("deny"), deny.dataRepresentation)
        try storage.set(Self.slot("enc"), enc.dataRepresentation)
        try savePIN(pin)
    }

    /// A typed PIN goes straight to the key. Otherwise Face ID opens the stored PIN (same context, so the key does not
    /// ask again); without it, iOS asks for the PIN.
    private func approveKey(pin: String?) throws -> SecureEnclave.P256.Signing.PrivateKey {
        let ctx = LAContext()
        ctx.localizedReason = "Approve the request"
        if let pin = (pin?.isEmpty == false ? pin : nil) ?? storedPIN(ctx) {
            ctx.setCredential(Data(pin.utf8), type: .applicationPassword)
        }
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: try need("approve"), authenticationContext: ctx)
    }

    private static let pinItem: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                                 kSecAttrService as String: "com.eff3.interloper.pin",
                                                 kSecAttrAccount as String: "approve"]

    /// Keeps the app PIN where only Face ID (current enrollment) can read it.
    private func savePIN(_ pin: String) throws {
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                       .biometryCurrentSet, &err)
        else { throw err!.takeRetainedValue() as Error }
        SecItemDelete(Self.pinItem as CFDictionary)
        var q = Self.pinItem
        q[kSecValueData as String] = Data(pin.utf8)
        q[kSecAttrAccessControl as String] = ac
        let st = SecItemAdd(q as CFDictionary, nil)
        guard st == errSecSuccess else { throw KeychainError(status: st) }
    }

    /// The stored PIN, after Face ID on ctx; nil if there is none or Face ID failed or was cancelled.
    private func storedPIN(_ ctx: LAContext) -> String? {
        var q = Self.pinItem
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecUseAuthenticationContext as String] = ctx
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(decoding: d, as: UTF8.self)
    }

    private func need(_ name: String) throws -> Data {
        guard let d = try storage.get(Self.slot(name)) else { throw ProtocolError.untrusted("no \(name) key; enroll first") }
        return d
    }

    public func publicKeys() throws -> DevicePublicKeys {
        // Reading the public half of the approve key does not use the key, so no prompt.
        DevicePublicKeys(
            approve: try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: need("approve")).publicKey.x963Representation,
            deny: try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: need("deny")).publicKey.x963Representation,
            enc: try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: need("enc")).publicKey.x963Representation)
    }

    public func signApprove(_ data: Data, pin: String?) throws -> Data {
        let sig: Data
        do {
            sig = try approveKey(pin: pin).signature(for: data).rawRepresentation
        } catch let e as TKError where e.code == .corruptedData || e.code == .authenticationFailed {
            // The app PIN is part of how the Secure Enclave opens the key: a wrong one reads as corrupted key data.
            throw ApproveKeyError.wrongPIN
        }
        // A typed PIN that worked is kept for Face ID: keys made before the stored PIN, or after Face ID re-enrollment
        // (which makes the stored copy unreadable).
        if let pin, !pin.isEmpty { try? savePIN(pin) }
        return sig
    }

    public func signDeny(_ data: Data) throws -> Data {
        try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: need("deny")).signature(for: data).rawRepresentation
    }

    public func open(enc: Data, ciphertext: Data, info: Data) throws -> Data {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: need("enc"))
        var r = try HPKE.Recipient(privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256, info: info, encapsulatedKey: enc)
        return try r.open(ciphertext)
    }

    public func reset() throws {
        for n in ["approve", "deny", "enc"] { try storage.delete(Self.slot(n)) }
        SecItemDelete(Self.pinItem as CFDictionary)
    }
}

// MARK: - Software (simulator, tests)

/// Plain CryptoKit keys kept in `storage`. Anyone who can read the storage can approve: testing only.
public final class SoftwareKeyStore: KeyStore, @unchecked Sendable {
    private let storage: SecretStorage
    public let kind = KeyStoreKind.software

    public init(storage: SecretStorage) { self.storage = storage }

    /// A store holding the given raw P-256 scalars (CryptoKit rawRepresentation), for interop tests.
    public convenience init(approveRaw: Data, denyRaw: Data, encRaw: Data) throws {
        self.init(storage: MemoryStorage())
        _ = try P256.Signing.PrivateKey(rawRepresentation: approveRaw)
        _ = try P256.Signing.PrivateKey(rawRepresentation: denyRaw)
        _ = try P256.KeyAgreement.PrivateKey(rawRepresentation: encRaw)
        try storage.set("sw.approve", approveRaw)
        try storage.set("sw.deny", denyRaw)
        try storage.set("sw.enc", encRaw)
    }

    public func hasKeys() -> Bool {
        ["approve", "deny", "enc"].allSatisfy { (try? storage.get("sw.\($0)")) != nil }
    }

    public func generate(pin: String?) throws {
        try storage.set("sw.approve", P256.Signing.PrivateKey().rawRepresentation)
        try storage.set("sw.deny", P256.Signing.PrivateKey().rawRepresentation)
        try storage.set("sw.enc", P256.KeyAgreement.PrivateKey().rawRepresentation)
    }

    private func need(_ name: String) throws -> Data {
        guard let d = try storage.get("sw.\(name)") else { throw ProtocolError.untrusted("no \(name) key; enroll first") }
        return d
    }

    public func publicKeys() throws -> DevicePublicKeys {
        DevicePublicKeys(
            approve: try P256.Signing.PrivateKey(rawRepresentation: need("approve")).publicKey.x963Representation,
            deny: try P256.Signing.PrivateKey(rawRepresentation: need("deny")).publicKey.x963Representation,
            enc: try P256.KeyAgreement.PrivateKey(rawRepresentation: need("enc")).publicKey.x963Representation)
    }

    public func signApprove(_ data: Data, pin: String?) throws -> Data {
        try P256.Signing.PrivateKey(rawRepresentation: need("approve")).signature(for: data).rawRepresentation
    }

    public func signDeny(_ data: Data) throws -> Data {
        try P256.Signing.PrivateKey(rawRepresentation: need("deny")).signature(for: data).rawRepresentation
    }

    public func open(enc: Data, ciphertext: Data, info: Data) throws -> Data {
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: need("enc"))
        var r = try HPKE.Recipient(privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256, info: info, encapsulatedKey: enc)
        return try r.open(ciphertext)
    }

    public func reset() throws {
        for n in ["approve", "deny", "enc"] { try storage.delete("sw.\(n)") }
    }
}
