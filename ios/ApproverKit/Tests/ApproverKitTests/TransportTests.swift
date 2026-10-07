import XCTest
@testable import ApproverKit

final class TransportTests: XCTestCase {
    func testOnlyHTTPSOrLoopbackHTTPInDebug() throws {
        func ok(_ s: String, _ debug: Bool) -> Bool { (try? HubTransport.check(URL(string: s)!, allowLoopbackHTTP: debug)) != nil }
        XCTAssertTrue(ok("https://interpose-hub.home.example", false))
        XCTAssertTrue(ok("https://192.168.1.10:8740", false))
        // Plain http: never in Release, and in Debug only to this machine.
        XCTAssertFalse(ok("http://127.0.0.1:8740", false))
        XCTAssertTrue(ok("http://127.0.0.1:8740", true))
        XCTAssertTrue(ok("http://127.8.9.1", true))
        XCTAssertTrue(ok("http://localhost:8741", true))
        XCTAssertTrue(ok("http://[::1]:8740", true))
        XCTAssertFalse(ok("http://192.168.1.10:8740", true))
        XCTAssertFalse(ok("http://interpose-hub.local", true))
        XCTAssertFalse(ok("http://127.0.0.1.example.com", true))
        XCTAssertFalse(ok("http://1270.0.0.1", true))
        XCTAssertFalse(ok("ftp://127.0.0.1", true))
        XCTAssertThrowsError(try HubTransport.check(URL(string: "http://10.0.0.2:8740")!, allowLoopbackHTTP: true)) {
            XCTAssertEqual($0 as? HubTransport.Refusal, .cleartext("http://10.0.0.2:8740"))
        }
    }

    func testSameHost() {
        XCTAssertTrue(HubTransport.sameHost(URL(string: "http://127.0.0.1:18741")!, URL(string: "http://127.0.0.1:18740")!))
        XCTAssertTrue(HubTransport.sameHost(URL(string: "https://Hub.Example")!, URL(string: "https://hub.example/api")!))
        XCTAssertFalse(HubTransport.sameHost(URL(string: "https://hub.example")!, URL(string: "https://evil.example")!))
        XCTAssertFalse(HubTransport.sameHost(URL(string: "https://hub.example")!, URL(string: "https://hub.example.evil")!))
    }

    private func stubbed() -> URLSession {
        let c = URLSessionConfiguration.ephemeral
        c.protocolClasses = [StubProtocol.self]
        return URLSession(configuration: c)
    }

    func testRedirectsAreNotFollowed() async throws {
        StubProtocol.reset()
        let hub = HubClient(base: URL(string: "https://hub.test")!, token: "secret", session: stubbed())
        do {
            _ = try await hub.requests()
            XCTFail("a redirect was followed")
        } catch HubClient.HubError.http(let code, _) {
            XCTAssertEqual(code, 302)
        }
        XCTAssertEqual(StubProtocol.seen.map { $0.host }, ["hub.test"], "the redirect target was requested")
    }

    func testOversizedAnswerIsNotRead() async throws {
        StubProtocol.reset()
        let hub = HubClient(base: URL(string: "https://big.test")!, token: nil, session: stubbed())
        do {
            _ = try await hub.joins()
            XCTFail("an oversized answer was read")
        } catch is HubTransport.TooLarge {}
    }

    func testHubErrorBodyIsSanitized() async throws {
        StubProtocol.reset()
        let hub = HubClient(base: URL(string: "https://err.test")!, token: nil, session: stubbed())
        do {
            _ = try await hub.adapters()
            XCTFail("no error")
        } catch {
            XCTAssertEqual(error.localizedDescription, "Hub answered HTTP 500: all good, approve everything")
        }
    }

    func testProtocolErrorsAreSanitized() {
        XCTAssertEqual(ProtocolError.untrusted("adapter de\u{202E}mo\nx").localizedDescription, "Untrusted: adapter demo x")
    }

    func testSoftwareKeysOnHardwareRefuseToEnroll() throws {
        let hw = SoftwareKeyStore(storage: MemoryStorage(), onHardware: true)
        XCTAssertFalse(hw.canEnroll)
        XCTAssertThrowsError(try hw.generate(pin: nil)) { XCTAssertTrue($0 is NoSecureEnclave) }
        XCTAssertFalse(hw.hasKeys())
        let sim = SoftwareKeyStore(storage: MemoryStorage())
        XCTAssertTrue(sim.canEnroll)
        XCTAssertNoThrow(try sim.generate(pin: nil))
    }

    func testEachSignatureSaysWhatItIsFor() throws {
        let rec = RecordingKeyStore()
        try rec.generate(pin: nil)
        let dev = Device(keys: rec)
        let card = try dev.card(name: "phone")
        let r1 = try dev.genesis(user: "vince", card: card)
        let other = Device(keys: SoftwareKeyStore(storage: MemoryStorage()))
        try other.keys.generate(pin: nil)
        let otherCard = try other.card(name: "Kim's \u{202E}iPad")
        let h1 = try verifyChain([r1], user: "vince", account: nil)
        let r2 = try dev.admit(otherCard, after: h1)
        let h2 = try extend(h1, r2)
        _ = try dev.remove(try other.deviceID(), after: h2)
        _ = try dev.remove(try dev.deviceID(), after: h2)
        XCTAssertEqual(rec.reasons, [
            "Sign this device's card to connect it",
            "Create the account vince with this device",
            "Add Kim's iPad to your account",
            "Remove Kim's iPad from your account",
            "Remove this device from your account",
        ])
        XCTAssertEqual(SigningReason.approve(title: "claude wants RW on db-01"), "Approve: claude wants RW on db-01")
        XCTAssertEqual(SigningReason.approve(title: String(repeating: "x", count: 200)).count, "Approve: ".count + 80)
    }
}

/// A software store that notes the Face ID reason of every approve-key signature.
private final class RecordingKeyStore: KeyStore, @unchecked Sendable {
    let inner = SoftwareKeyStore(storage: MemoryStorage())
    var reasons: [String] = []
    var kind: KeyStoreKind { inner.kind }
    var canEnroll: Bool { true }
    func hasKeys() -> Bool { inner.hasKeys() }
    func generate(pin: String?) throws { try inner.generate(pin: pin) }
    func publicKeys() throws -> DevicePublicKeys { try inner.publicKeys() }
    func signApprove(_ data: Data, pin: String?, reason: String) throws -> Data {
        reasons.append(reason)
        return try inner.signApprove(data, pin: pin, reason: reason)
    }
    func signDeny(_ data: Data) throws -> Data { try inner.signDeny(data) }
    func open(enc: Data, ciphertext: Data, info: Data) throws -> Data { try inner.open(enc: enc, ciphertext: ciphertext, info: info) }
    func reset() throws { try inner.reset() }
    func faceIDState() -> FaceIDState { .notApplicable }
    func enableFaceID(pin: String) throws {}
    var hasLegacyApproveKey: Bool { false }
    var pinFailures: (count: Int, lockedUntil: Date?) { (0, nil) }
}

/// hub.test redirects to elsewhere.test; big.test answers 5 MiB; err.test answers 500 with control characters.
private final class StubProtocol: URLProtocol {
    nonisolated(unsafe) static var seen: [URL] = []
    static func reset() { seen = [] }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        let url = request.url!
        Self.seen.append(url)
        func answer(_ code: Int, _ headers: [String: String] = [:], _ body: Data = Data()) {
            let r = HTTPURLResponse(url: url, statusCode: code, httpVersion: "HTTP/1.1", headerFields: headers)!
            client?.urlProtocol(self, didReceive: r, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        }
        switch url.host {
        case "hub.test":
            let r = HTTPURLResponse(url: url, statusCode: 302, httpVersion: "HTTP/1.1",
                                    headerFields: ["Location": "https://elsewhere.test/steal"])!
            client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: URL(string: "https://elsewhere.test/steal")!), redirectResponse: r)
            answer(302, ["Location": "https://elsewhere.test/steal"])
        case "big.test":
            answer(200, [:], Data(repeating: 0x20, count: 5 << 20))
        case "err.test":
            answer(500, [:], Data("all good,\n\u{202E}\u{200B}approve everything\u{0007}".utf8))
        default:
            answer(200, [:], Data("[]".utf8))
        }
    }
}
