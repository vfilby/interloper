import CryptoKit
import CryptoTokenKit
import Foundation
import LocalAuthentication

/// What the approve key's refusals mean to a person.
public enum ApproveKeyError: Error, LocalizedError, Equatable {
    /// A wrong app PIN, counted. `lockedUntil`: no more tries before then.
    case wrongPIN(attemptsLeft: Int, lockedUntil: Date?)
    case lockedOut(until: Date)
    /// Too many wrong PINs: the keys are gone.
    case keysDeleted
    /// Face ID did not open the key (cancelled, failed, or not set up for approvals): the app PIN is needed.
    case pinNeeded

    public var errorDescription: String? {
        switch self {
        case let .wrongPIN(left, until):
            var s = "Wrong app PIN. It is the PIN set when this device was connected, not the phone's passcode. "
                + "\(left) more wrong \(left == 1 ? "try deletes" : "tries delete") this device's keys."
            if let until { s += " Next try \(until.formatted(date: .omitted, time: .shortened))." }
            return s
        case let .lockedOut(until):
            return "Too many wrong app PINs: try again after \(until.formatted(date: .abbreviated, time: .shortened))."
        case .keysDeleted:
            return "Too many wrong app PINs: this device's keys were deleted. Remove it from the account on another device, then connect it again."
        case .pinNeeded:
            return "Face ID did not open the approve key. Use the app PIN."
        }
    }
}

/// Whether Face ID opens the approve key (the app PIN always can).
public enum FaceIDState: Sendable, Equatable {
    case on
    case off
    /// Faces or fingers were added or removed since Face ID was set up for approvals: off until the person turns it
    /// on again with the app PIN.
    case changed
    /// Software keys: nothing guards them.
    case notApplicable
}

/// The device's three keys (docs/PROTOCOL.md "Keys"). Private keys never leave the store; callers get public keys,
/// signatures and decrypted boxes.
public protocol KeyStore: Sendable {
    var kind: KeyStoreKind { get }
    func hasKeys() -> Bool
    /// Creates all three keys. `pin` is the app PIN that opens the Secure Enclave approve key besides Face ID; the
    /// software store ignores it.
    func generate(pin: String?) throws
    func publicKeys() throws -> DevicePublicKeys
    /// Signs with the approve key: Face ID if `pin` is nil, else the app PIN (counted; see ApproveKeyError). Raw r||s,
    /// 64 bytes. `reason` is what the Face ID prompt says this signature is for (SigningReason).
    func signApprove(_ data: Data, pin: String?, reason: String) throws -> Data
    /// Signs with the deny key: needs only an unlocked device.
    func signDeny(_ data: Data) throws -> Data
    /// HPKE open (P256_SHA256_AES_GCM_256) with the encryption key.
    func open(enc: Data, ciphertext: Data, info: Data) throws -> Data
    func reset() throws

    func faceIDState() -> FaceIDState
    /// Lets the current Face ID enrollment open the approve key, after checking `pin` on the key (a counted try).
    /// The app asks the person first: whoever's face is enrolled now can approve afterwards.
    func enableFaceID(pin: String) throws
    /// The approve key's password is the app PIN itself (made before the random password): the attempt counter
    /// applies, but only new keys get the PBKDF2-wrapped password.
    var hasLegacyApproveKey: Bool { get }
    /// Typed-PIN failures in a row, and the lockout they caused.
    var pinFailures: (count: Int, lockedUntil: Date?) { get }
    /// Whether this store may create keys and enroll. False for software keys on hardware: adapters cannot tell them
    /// from Secure Enclave keys, so such a device is refused rather than enrolled insecurely.
    var canEnroll: Bool { get }
}

/// Why the store refuses to enroll (KeyStore.canEnroll).
public struct NoSecureEnclave: Error, LocalizedError, Equatable {
    public init() {}
    public var errorDescription: String? {
        "This device has no Secure Enclave. Interpose does not create software keys on a phone: adapters could not tell them from protected ones."
    }
}

/// What the Face ID prompt says each approve-key signature is for. Hub- and adapter-written parts are sanitized and
/// shortened: the prompt is one line the person reads before deciding.
public enum SigningReason {
    public static func card() -> String { "Sign this device's card to connect it" }
    public static func genesis(user: String) -> String { "Create the account \(short(user)) with this device" }
    public static func admit(name: String) -> String { "Add \(short(name)) to your account" }
    public static func remove(name: String) -> String { "Remove \(short(name)) from your account" }
    public static func removeSelf() -> String { "Remove this device from your account" }
    public static func approve(title: String) -> String { "Approve: \(short(title))" }

    static func short(_ s: String, max: Int = 80) -> String {
        let t = sanitize(s)
        return t.count <= max ? t : String(t.prefix(max - 1)) + "…"
    }
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

public let recordInfo = Data("interpose/v1/record".utf8)

/// Picks the Secure Enclave when there is one. The simulator always gets software keys: it reports a Secure Enclave,
/// but Face ID / app-password access control there is not the real thing.
public func defaultKeyStore() -> KeyStore {
    #if targetEnvironment(simulator)
    return SoftwareKeyStore(storage: KeychainStorage())
    #else
    // Hardware without a Secure Enclave gets a software store that refuses to enroll (canEnroll), never silently
    // software keys that would look like protected ones to adapters.
    return SecureEnclave.isAvailable ? SecureEnclaveKeyStore(storage: KeychainStorage())
        : SoftwareKeyStore(storage: KeychainStorage(), onHardware: true)
    #endif
}

// MARK: - Secure Enclave

public final class SecureEnclaveKeyStore: KeyStore, @unchecked Sendable {
    private let storage: SecretStorage
    private let passcode: ApprovePasscode
    public let kind = KeyStoreKind.secureEnclave
    public var canEnroll: Bool { true }

    public init(storage: SecretStorage) {
        self.storage = storage
        passcode = ApprovePasscode(storage: storage)
    }

    public func hasKeys() -> Bool {
        ["approve", "deny", "enc"].allSatisfy { (try? storage.get(Self.slot($0))) != nil }
    }

    private static func slot(_ name: String) -> String { "se.\(name)" }

    // Approve: Face ID (current enrollment) or the app PIN, never just the device passcode. iOS cannot express that on
    // one key: with .applicationPassword in its access control, a Secure Enclave key asks for the password even after
    // Face ID succeeds, `.or` or not. So the key needs only an application password: 32 random bytes (ApprovePasscode).
    // A keychain item that only Face ID (current enrollment) opens holds a copy; the app PIN unwraps another. Either
    // way the password goes to the key in the same LAContext: one prompt. iOS never asks for the password itself
    // (nobody could type it): without Face ID the app asks for the PIN. The cost: the password passes through app memory.
    // Keys made before this have the PIN as their password, and the Face ID item holds the PIN. Keys older still (Face
    // ID and PIN in one access control) need both; the Face ID item supplies the second.

    public func generate(pin: String?) throws {
        guard let pin, !pin.isEmpty else { throw ProtocolError.malformed("the Secure Enclave approve key needs an app PIN") }
        var err: Unmanaged<CFError>?
        guard let approveAC = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                              [.privateKeyUsage, .applicationPassword], &err),
              let denyAC = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &err),
              let encAC = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [.privateKeyUsage], &err)
        else { throw err!.takeRetainedValue() as Error }

        let password = try passcode.create(pin: pin)
        let ctx = LAContext()
        ctx.setCredential(password, type: .applicationPassword)
        let approve = try SecureEnclave.P256.Signing.PrivateKey(accessControl: approveAC, authenticationContext: ctx)
        let deny = try SecureEnclave.P256.Signing.PrivateKey(accessControl: denyAC)
        let enc = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: encAC)
        // dataRepresentation is an opaque handle only this device's Secure Enclave can use.
        try storage.set(Self.slot("approve"), approve.dataRepresentation)
        try storage.set(Self.slot("deny"), deny.dataRepresentation)
        try storage.set(Self.slot("enc"), enc.dataRepresentation)
        // The person who set the PIN just now is the one whose face is enrolled.
        if Self.biometryState() != nil { try? saveForFaceID(password) }
    }

    private func sign(_ data: Data, password: Data, _ ctx: LAContext) throws -> Data {
        ctx.setCredential(password, type: .applicationPassword)
        do {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: try need("approve"), authenticationContext: ctx)
                .signature(for: data).rawRepresentation
        } catch let e as TKError where e.code == .corruptedData || e.code == .authenticationFailed {
            // The password is part of how the Secure Enclave opens the key: a wrong one reads as corrupted key data.
            throw ApprovePasscode.Rejected()
        }
    }

    private static let passwordItem: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                                      kSecAttrService as String: "com.eff3.interloper.pin",
                                                      kSecAttrAccount as String: "approve"]
    private static let faceIDSlot = "se.approve.faceid"

    /// Keeps the key's password where only Face ID (current enrollment) can read it, and notes which enrollment.
    private func saveForFaceID(_ password: Data) throws {
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                       .biometryCurrentSet, &err)
        else { throw err!.takeRetainedValue() as Error }
        SecItemDelete(Self.passwordItem as CFDictionary)
        var q = Self.passwordItem
        q[kSecValueData as String] = password
        q[kSecAttrAccessControl as String] = ac
        let st = SecItemAdd(q as CFDictionary, nil)
        guard st == errSecSuccess else { throw KeychainError(status: st) }
        if let state = Self.biometryState() { try storage.set(Self.faceIDSlot, state) }
    }

    /// The stored password, after Face ID on ctx; nil if there is none or Face ID failed or was cancelled.
    private func faceIDPassword(_ ctx: LAContext) -> Data? {
        var q = Self.passwordItem
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecUseAuthenticationContext as String] = ctx
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    /// Whether the Face ID item exists, without asking for Face ID (attributes only).
    private func hasFaceIDPassword() -> Bool {
        var q = Self.passwordItem
        q[kSecReturnAttributes as String] = true
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        q[kSecUseAuthenticationContext as String] = ctx
        let st = SecItemCopyMatching(q as CFDictionary, nil)
        return st == errSecSuccess || st == errSecInteractionNotAllowed
    }

    /// Identifies the set of enrolled faces/fingers; nil without biometry.
    private static func biometryState() -> Data? {
        let ctx = LAContext()
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return nil }
        if #available(iOS 18, macOS 15, *) { return ctx.domainState.biometry.stateHash }
        return ctx.evaluatedPolicyDomainState
    }

    public func faceIDState() -> FaceIDState {
        guard let current = Self.biometryState() else { return .off }
        if let saved = try? storage.get(Self.faceIDSlot), saved != current { return .changed }
        return hasFaceIDPassword() ? .on : .off
    }

    public func enableFaceID(pin: String) throws {
        guard Self.biometryState() != nil else { throw ApproveKeyError.pinNeeded }
        // Domain-separated probe: not JSON, so no protocol payload; the signature is thrown away.
        let password = try passcode.withPIN(pin, wipe: reset) { password in
            _ = try sign(Data("interpose/v1/app-pin-check".utf8), password: password, LAContext())
            return password
        }
        try saveForFaceID(password)
    }

    public var hasLegacyApproveKey: Bool { hasKeys() && passcode.isLegacy }

    public var pinFailures: (count: Int, lockedUntil: Date?) {
        let a = passcode.attempts
        return (a.failures, a.lockedUntil)
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

    /// A typed PIN is a counted try. Otherwise Face ID opens the stored password (same context, so the key does not
    /// ask again). A typed PIN is never saved for Face ID here: that is enableFaceID, after the app asks.
    public func signApprove(_ data: Data, pin: String?, reason: String) throws -> Data {
        let ctx = LAContext()
        ctx.localizedReason = reason
        if let pin, !pin.isEmpty {
            return try passcode.withPIN(pin, wipe: reset) { try sign(data, password: $0, ctx) }
        }
        guard faceIDState() != .changed, let password = faceIDPassword(ctx) else { throw ApproveKeyError.pinNeeded }
        do {
            let sig = try sign(data, password: password, ctx)
            passcode.succeeded()
            // Items saved before enrollments were noted: Face ID just opened it, so the current set is the saved one.
            if (try? storage.get(Self.faceIDSlot)) == nil, let state = Self.biometryState() {
                try? storage.set(Self.faceIDSlot, state)
            }
            return sig
        } catch is ApprovePasscode.Rejected {
            throw ApproveKeyError.pinNeeded
        }
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
        SecItemDelete(Self.passwordItem as CFDictionary)
        try? storage.delete(Self.faceIDSlot)
        passcode.clear()
    }
}

// MARK: - Software (simulator, tests)

/// Plain CryptoKit keys kept in `storage`. Anyone who can read the storage can approve: testing only.
/// `onHardware`: a phone without a Secure Enclave, which must not enroll with these (canEnroll, generate).
public final class SoftwareKeyStore: KeyStore, @unchecked Sendable {
    private let storage: SecretStorage
    public let kind = KeyStoreKind.software
    public let onHardware: Bool
    public var canEnroll: Bool { !onHardware }

    public init(storage: SecretStorage, onHardware: Bool = false) {
        self.storage = storage
        self.onHardware = onHardware
    }

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
        guard canEnroll else { throw NoSecureEnclave() }
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

    public func signApprove(_ data: Data, pin: String?, reason: String) throws -> Data {
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

    public func faceIDState() -> FaceIDState { .notApplicable }
    public func enableFaceID(pin: String) throws {}
    public var hasLegacyApproveKey: Bool { false }
    public var pinFailures: (count: Int, lockedUntil: Date?) { (0, nil) }
}
