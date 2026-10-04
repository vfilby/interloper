import CryptoKit
import Foundation
import LocalAuthentication

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

    public func generate(pin: String?) throws {
        var err: Unmanaged<CFError>?
        // Approve: Face ID (current enrollment) or the app PIN, never just the device passcode.
        guard let approveAC = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                              [.privateKeyUsage, .biometryCurrentSet, .or, .applicationPassword], &err),
              let denyAC = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &err),
              let encAC = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage], &err)
        else { throw err!.takeRetainedValue() as Error }

        let ctx = LAContext()
        if let pin, !pin.isEmpty { ctx.setCredential(Data(pin.utf8), type: .applicationPassword) }
        let approve = try SecureEnclave.P256.Signing.PrivateKey(accessControl: approveAC, authenticationContext: ctx)
        let deny = try SecureEnclave.P256.Signing.PrivateKey(accessControl: denyAC)
        let enc = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: encAC)
        // dataRepresentation is an opaque handle only this device's Secure Enclave can use.
        try storage.set(Self.slot("approve"), approve.dataRepresentation)
        try storage.set(Self.slot("deny"), deny.dataRepresentation)
        try storage.set(Self.slot("enc"), enc.dataRepresentation)
    }

    private func approveKey(pin: String?) throws -> SecureEnclave.P256.Signing.PrivateKey {
        let ctx = LAContext()
        ctx.localizedReason = "Approve the request"
        if let pin, !pin.isEmpty { ctx.setCredential(Data(pin.utf8), type: .applicationPassword) }
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: try need("approve"), authenticationContext: ctx)
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
        try approveKey(pin: pin).signature(for: data).rawRepresentation
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
