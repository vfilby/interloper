import XCTest
@testable import ApproverKit

final class AppPINTests: XCTestCase {
    /// A clock the test moves by hand.
    final class Clock: @unchecked Sendable {
        var now = Date(timeIntervalSince1970: 1_800_000_000)
    }

    /// Stands in for the Secure Enclave approve key: accepts one password, refuses any other.
    private func key(_ right: Data) -> (Data) throws -> String {
        { password in
            guard password == right else { throw ApprovePasscode.Rejected() }
            return "signed"
        }
    }

    private func passcode(_ storage: SecretStorage, _ clock: Clock) -> ApprovePasscode {
        ApprovePasscode(storage: storage, iterations: 1000, now: { clock.now })
    }

    func testPBKDF2Vectors() {
        // PBKDF2-HMAC-SHA256, P = "password", S = "salt" (RFC 7914 section 11 and common test vectors).
        XCTAssertEqual(ApprovePasscode.derive("password", salt: Data("salt".utf8), iterations: 1).hex,
                       "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        XCTAssertEqual(ApprovePasscode.derive("password", salt: Data("salt".utf8), iterations: 4096).hex,
                       "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        XCTAssertGreaterThanOrEqual(ApprovePasscode.iterations, 600_000)
    }

    func testPINRules() {
        XCTAssertNotNil(AppPIN.problem("1234567"))
        XCTAssertNil(AppPIN.problem("12345678"))
        XCTAssertNil(AppPIN.problem("correct horse"))
        XCTAssertThrowsError(try ApprovePasscode(storage: MemoryStorage()).create(pin: "123456"))
    }

    func testRandomPasswordWrappedUnderPIN() throws {
        let s = MemoryStorage()
        let p = passcode(s, Clock())
        let password = try p.create(pin: "open sesame")
        XCTAssertEqual(password.count, 32)
        XCTAssertNotEqual(password, Data("open sesame".utf8))
        XCTAssertFalse(p.isLegacy)
        XCTAssertEqual(try p.password(forPIN: "open sesame"), password)
        // A wrong PIN unwraps to some other password, with no error: only the key can tell.
        let wrong = try p.password(forPIN: "open sesamE")
        XCTAssertEqual(wrong.count, 32)
        XCTAssertNotEqual(wrong, password)
        // Neither the PIN nor the password is stored.
        let stored = try XCTUnwrap(s.get(ApprovePasscode.wrapSlot))
        XCTAssertNil(stored.range(of: password))
        XCTAssertNil(stored.range(of: Data("open sesame".utf8)))
        // Each set of keys gets its own password.
        XCTAssertNotEqual(try passcode(MemoryStorage(), Clock()).create(pin: "open sesame"), password)
    }

    func testLegacyKeysUseThePINAsPassword() throws {
        let p = passcode(MemoryStorage(), Clock())
        XCTAssertTrue(p.isLegacy)
        XCTAssertEqual(try p.password(forPIN: "123456"), Data("123456".utf8))
        // The counter applies to them too.
        XCTAssertThrowsError(try p.withPIN("000000", wipe: {}, key(Data("123456".utf8))))
        XCTAssertEqual(p.attempts.failures, 1)
        XCTAssertEqual(try p.withPIN("123456", wipe: {}, key(Data("123456".utf8))), "signed")
        XCTAssertEqual(p.attempts.failures, 0)
    }

    func testLockoutGrowsAndWipesAfterTenFailures() throws {
        let clock = Clock()
        let s = MemoryStorage()
        let p = passcode(s, clock)
        let right = try p.create(pin: "the right pin")
        var wiped = 0
        let policy = PINAttemptPolicy()
        XCTAssertEqual((1...9).map { policy.lockout(afterFailures: $0) },
                       [0, 0, 0, 60, 240, 960, 3840, 15360, 61440])

        for n in 1...9 {
            XCTAssertThrowsError(try p.withPIN("guess \(n)", wipe: { wiped += 1 }, key(right))) { e in
                let wait = policy.lockout(afterFailures: n)
                XCTAssertEqual(e as? ApproveKeyError,
                               .wrongPIN(attemptsLeft: 10 - n, lockedUntil: wait > 0 ? clock.now.addingTimeInterval(wait) : nil))
            }
            XCTAssertEqual(p.attempts.failures, n)
            if let until = p.attempts.lockedUntil {
                // Locked: even the right PIN is not tried, and the wait does not count as a failure.
                XCTAssertThrowsError(try p.withPIN("the right pin", wipe: { wiped += 1 }, key(right))) {
                    XCTAssertEqual($0 as? ApproveKeyError, .lockedOut(until: until))
                }
                XCTAssertEqual(p.attempts.failures, n)
                clock.now = until
            }
        }
        XCTAssertEqual(wiped, 0)
        XCTAssertThrowsError(try p.withPIN("guess 10", wipe: { wiped += 1 }, key(right))) {
            XCTAssertEqual($0 as? ApproveKeyError, .keysDeleted)
        }
        XCTAssertEqual(wiped, 1)
    }

    func testRightPINStartsOver() throws {
        let clock = Clock()
        let p = passcode(MemoryStorage(), clock)
        let right = try p.create(pin: "the right pin")
        for _ in 1...4 { XCTAssertThrowsError(try p.withPIN("nope nope", wipe: {}, key(right))) }
        clock.now = try XCTUnwrap(p.attempts.lockedUntil)
        XCTAssertEqual(try p.withPIN("the right pin", wipe: {}, key(right)), "signed")
        XCTAssertEqual(p.attempts, .init())

        // So does Face ID.
        XCTAssertThrowsError(try p.withPIN("nope nope", wipe: {}, key(right)))
        p.succeeded()
        XCTAssertEqual(p.attempts, .init())
    }

    func testFailureIsWrittenBeforeTheKeyIsTried() throws {
        let s = MemoryStorage()
        let p = passcode(s, Clock())
        _ = try p.create(pin: "the right pin")
        // As if the app were killed while the Secure Enclave checks the PIN: the try already counts.
        _ = try? p.withPIN("a guess!", wipe: {}) { _ -> String in
            XCTAssertEqual(p.attempts.failures, 1)
            throw ApprovePasscode.Rejected()
        }
        // A survivor of a kill: a new store on the same storage sees the count.
        XCTAssertEqual(passcode(s, Clock()).attempts.failures, 1)
    }

    func testOtherErrorsDoNotCount() throws {
        let p = passcode(MemoryStorage(), Clock())
        _ = try p.create(pin: "the right pin")
        struct Cancelled: Error {}
        XCTAssertThrowsError(try p.withPIN("the right pin", wipe: {}) { _ -> String in throw Cancelled() }) {
            XCTAssertTrue($0 is Cancelled)
        }
        XCTAssertEqual(p.attempts.failures, 0)
    }

    func testWipeIsRetriedAfterItFailed() throws {
        // A wipe that failed last time is tried again before any PIN.
        let s = MemoryStorage()
        let p = passcode(s, Clock())
        let right = try p.create(pin: "the right pin")
        try s.set(ApprovePasscode.attemptsSlot, try JSONEncoder().encode(ApprovePasscode.Attempts(failures: 10)))
        var wiped = false
        XCTAssertThrowsError(try p.withPIN("the right pin", wipe: { wiped = true }, key(right))) {
            XCTAssertEqual($0 as? ApproveKeyError, .keysDeleted)
        }
        XCTAssertTrue(wiped)
    }

    func testClear() throws {
        let s = MemoryStorage()
        let p = passcode(s, Clock())
        _ = try p.create(pin: "the right pin")
        p.clear()
        XCTAssertNil(try s.get(ApprovePasscode.wrapSlot))
        XCTAssertNil(try s.get(ApprovePasscode.attemptsSlot))
    }
}

private extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
