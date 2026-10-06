import CommonCrypto
import CryptoKit
import Foundation

/// What a new app PIN must be. Letters are allowed: a debugger on an unlocked phone can skip the attempt counter and
/// try PINs on the Secure Enclave directly, so the PIN's length is what bounds that attack.
public enum AppPIN {
    public static let minimumLength = 8

    /// Why `pin` cannot be a new app PIN, or nil if it can.
    public static func problem(_ pin: String) -> String? {
        pin.count < minimumLength ? "The app PIN needs at least \(minimumLength) characters (letters allowed)." : nil
    }
}

/// When typed PINs are refused: a few free mistakes, then a lockout that grows 4x with every failure, and after
/// `maxFailures` in a row the keys are deleted.
public struct PINAttemptPolicy: Sendable, Equatable {
    public var maxFailures = 10
    public var freeFailures = 3
    public var firstLockout: TimeInterval = 60
    public var factor: Double = 4

    public init() {}

    /// The wait after the nth failure in a row: 0 for the free ones, then 1 min, 4 min, 16 min, ~1 h, ~4 h, ~17 h.
    public func lockout(afterFailures n: Int) -> TimeInterval {
        n <= freeFailures ? 0 : firstLockout * pow(factor, Double(n - freeFailures - 1))
    }
}

/// The approve key's application password, and the counter on the app PIN that stands for it (docs/DESIGN.md,
/// "iOS app"). New keys get a random 32-byte password. Face ID keeps a copy of it (KeyStore.swift); the PIN path keeps
/// it XORed with PBKDF2-HMAC-SHA256(PIN). The wrap is deliberately not authenticated: every PIN unwraps to some
/// password, and only the Secure Enclave key can tell the right one, so a copy of the wrapped password is no use for
/// guessing PINs off the phone.
/// Keys made before this have the PIN itself as their password (`isLegacy`): the Secure Enclave cannot change it.
final class ApprovePasscode: @unchecked Sendable {
    static let iterations = 600_000
    static let wrapSlot = "se.approve.pinwrap"
    static let attemptsSlot = "se.approve.attempts"

    /// The key refused the password: `withPIN`'s body throws this for a wrong PIN.
    struct Rejected: Error {}

    struct Wrapped: Codable {
        var v = 1
        var salt: Data
        var iterations: Int
        var wrapped: Data
    }

    struct Attempts: Codable, Equatable {
        var failures = 0
        var lockedUntil: Date?
    }

    private let storage: SecretStorage
    private let policy: PINAttemptPolicy
    private let iterations: Int
    private let now: @Sendable () -> Date

    init(storage: SecretStorage, policy: PINAttemptPolicy = PINAttemptPolicy(), iterations: Int = ApprovePasscode.iterations,
         now: @escaping @Sendable () -> Date = { Date() }) {
        self.storage = storage
        self.policy = policy
        self.iterations = iterations
        self.now = now
    }

    var isLegacy: Bool { (try? storage.get(Self.wrapSlot)) == nil }

    /// A new random password, kept wrapped under `pin`. The caller creates the key with it.
    func create(pin: String) throws -> Data {
        if let p = AppPIN.problem(pin) { throw ProtocolError.malformed(p) }
        let password = Self.random(32)
        let salt = Self.random(16)
        let w = Wrapped(salt: salt, iterations: iterations, wrapped: Self.xor(password, Self.derive(pin, salt: salt, iterations: iterations)))
        try storage.set(Self.wrapSlot, try JSONEncoder().encode(w))
        try storage.set(Self.attemptsSlot, try JSONEncoder().encode(Attempts()))
        return password
    }

    /// The password a typed PIN stands for: right or wrong, only the key can tell.
    func password(forPIN pin: String) throws -> Data {
        guard let d = try storage.get(Self.wrapSlot) else { return Data(pin.utf8) }
        let w = try JSONDecoder().decode(Wrapped.self, from: d)
        guard w.v == 1, w.wrapped.count == 32 else { throw ProtocolError.malformed("stored app PIN wrap") }
        return Self.xor(w.wrapped, Self.derive(pin, salt: w.salt, iterations: w.iterations))
    }

    var attempts: Attempts {
        (try? storage.get(Self.attemptsSlot)).flatMap { $0 }.flatMap { try? JSONDecoder().decode(Attempts.self, from: $0) } ?? Attempts()
    }

    private func save(_ a: Attempts) throws { try storage.set(Self.attemptsSlot, try JSONEncoder().encode(a)) }

    /// Runs `use` with the password for a typed PIN, as one counted attempt. The failure is written down before the
    /// key sees the PIN, so stopping the app mid-attempt does not undo it. After `policy.maxFailures` failures in a row,
    /// `wipe` deletes the keys and this throws `keysDeleted`.
    func withPIN<T>(_ pin: String, wipe: () throws -> Void, _ use: (Data) throws -> T) throws -> T {
        let before = attempts
        if let until = before.lockedUntil, now() < until { throw ApproveKeyError.lockedOut(until: until) }
        if before.failures >= policy.maxFailures {
            try? wipe()
            throw ApproveKeyError.keysDeleted
        }
        let n = before.failures + 1
        try save(Attempts(failures: n))
        do {
            let r = try use(try password(forPIN: pin))
            try? save(Attempts())
            return r
        } catch is Rejected {
            if n >= policy.maxFailures {
                try? wipe()
                throw ApproveKeyError.keysDeleted
            }
            let wait = policy.lockout(afterFailures: n)
            let until = wait > 0 ? now().addingTimeInterval(wait) : nil
            try? save(Attempts(failures: n, lockedUntil: until))
            throw ApproveKeyError.wrongPIN(attemptsLeft: policy.maxFailures - n, lockedUntil: until)
        } catch {
            // Not the PIN (cancelled, no key, …): the attempt does not count.
            try? save(before)
            throw error
        }
    }

    /// Face ID opened the key: the person is here, so the count starts over.
    func succeeded() {
        if attempts != Attempts() { try? save(Attempts()) }
    }

    func clear() {
        try? storage.delete(Self.wrapSlot)
        try? storage.delete(Self.attemptsSlot)
    }

    static func derive(_ pin: String, salt: Data, iterations: Int) -> Data {
        var out = [UInt8](repeating: 0, count: 32)
        let st = pin.precomposedStringWithCanonicalMapping.withCString { pw in
            salt.withUnsafeBytes { s in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pw, strlen(pw), s.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                     CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations), &out, out.count)
            }
        }
        precondition(st == kCCSuccess, "PBKDF2 failed: \(st)")
        return Data(out)
    }

    private static func random(_ n: Int) -> Data {
        SymmetricKey(size: SymmetricKeySize(bitCount: n * 8)).withUnsafeBytes { Data($0) }
    }

    private static func xor(_ a: Data, _ b: Data) -> Data { Data(zip(a, b).map { $0 ^ $1 }) }
}
