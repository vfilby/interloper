import CryptoKit
import Foundation
import XCTest
@testable import ApproverKit

/// Interop with the Go side through internal/protocol/testdata/interop (see
/// internal/protocol/interop_test.go for how the files are made).
final class InteropTests: XCTestCase {
    struct GoSealed: Decodable {
        var deviceApproveRaw: String
        var deviceDenyRaw: String
        var deviceEncRaw: String
        var card: Envelope
        var adapterId: String
        var adapterKey: String
        var box: Sealed
        var recordPayload: String
        var now: Int64
    }

    struct SwiftDecision: Codable {
        var card: Envelope
        var decision: Envelope
    }

    static let interopDir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // ApproverKitTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // ApproverKit
        .deletingLastPathComponent() // ios
        .deletingLastPathComponent() // repo root
        .appendingPathComponent("internal/protocol/testdata/interop")

    func load<T: Decodable>(_ name: String) throws -> T {
        try Coders.decoder.decode(T.self, from: Data(contentsOf: Self.interopDir.appendingPathComponent(name)))
    }

    func fixture() throws -> (GoSealed, Device, [String: Data], HubRequest) {
        let g: GoSealed = try load("go-sealed.json")
        let keys = try SoftwareKeyStore(approveRaw: B64.decode(g.deviceApproveRaw), denyRaw: B64.decode(g.deviceDenyRaw),
                                        encRaw: B64.decode(g.deviceEncRaw))
        let pinned = [g.adapterId: try B64.decode(g.adapterKey)]
        let listing = HubRequest(id: "interop-1", adapter: g.adapterId, kind: "demo.test", createdAt: g.now,
                                 expiresAt: g.now + 900, box: g.box)
        return (g, Device(keys: keys), pinned, listing)
    }

    func testOpensGoSealedRecord() throws {
        let (g, dev, pinned, listing) = try fixture()
        let opened = try dev.open(listing, pinned: pinned)
        XCTAssertEqual(B64.encode(opened.payload), g.recordPayload)
        XCTAssertEqual(opened.record.title, "claude wants ADMIN on db-01")
        XCTAssertTrue(opened.record.isHighRisk)
        XCTAssertEqual(opened.record.onBehalfOf?.attestedBy, "chatbot@agent-host")
        XCTAssertEqual(opened.record.facts?.last?.level, "danger")
        XCTAssertEqual(opened.record.lease?.durationS, 7200)
    }

    func testDecisionVerifies() throws {
        let (g, dev, pinned, listing) = try fixture()
        let opened = try dev.open(listing, pinned: pinned)
        let pk = try dev.keys.publicKeys()

        let approve = try dev.decide(opened, user: "vince", approve: true)
        let p = try verifyES256(approve, x963: pk.approve)
        let d = try Coders.decoder.decode(Decision.self, from: p)
        XCTAssertEqual(d.decision, Decision.approve)
        XCTAssertEqual(d.t, PayloadType.decision)
        XCTAssertEqual(d.user, "vince")
        XCTAssertEqual(d.recordHash, B64.encode(sha256(try B64.decode(g.recordPayload))))
        XCTAssertEqual(d.nonce, opened.record.nonce)
        XCTAssertEqual(d.deviceId, pk.deviceID)

        let deny = try dev.decide(opened, user: "vince", approve: false)
        XCTAssertNoThrow(try verifyES256(deny, x963: pk.deny))
        XCTAssertThrowsError(try verifyES256(deny, x963: pk.approve), "deny must use the deny key")
    }

    func testCardMatchesGoCard() throws {
        let (g, dev, _, _) = try fixture()
        // The Go card for these keys and ours name the same device and keys.
        let goCard = try Coders.decoder.decode(DeviceCard.self, from: B64.decode(g.card.payload))
        let ours = try dev.card(name: "x")
        let card = try Coders.decoder.decode(DeviceCard.self, from: verifyES256(ours, x963: dev.keys.publicKeys().approve))
        XCTAssertEqual(card.deviceId, goCard.deviceId)
        XCTAssertEqual(card.encKey, goCard.encKey)
        XCTAssertEqual(ours.kid, card.deviceId)
    }

    /// Rewrites swift-decision.json (a CryptoKit-signed card and approval for the Go record), for Go's
    /// TestSwiftDecision. Run after the Go side rewrote go-sealed.json: INTERPOSE_WRITE_FIXTURE=1 swift test.
    func testWriteSwiftDecision() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["INTERPOSE_WRITE_FIXTURE"] == "1",
                          "set INTERPOSE_WRITE_FIXTURE=1 to rewrite internal/protocol/testdata/interop/swift-decision.json")
        let (g, dev, pinned, listing) = try fixture()
        let opened = try dev.open(listing, pinned: pinned)
        // Made at the record's own time, so Go can judge it then, however old the fixture is.
        let at = Date(timeIntervalSince1970: TimeInterval(g.now + 60))
        let out = SwiftDecision(card: try dev.card(name: "swift fixture"), decision: try dev.decide(opened, user: "vince", approve: true, now: at))
        try (Coders.encoder.encode(out) + Data("\n".utf8)).write(to: Self.interopDir.appendingPathComponent("swift-decision.json"))
    }

    func testSwiftDecisionFixtureCard() throws {
        let s: SwiftDecision = try load("swift-decision.json")
        let card = try Coders.decoder.decode(DeviceCard.self, from: B64.decode(s.card.payload))
        let ak = try B64.decode(card.approveKey)
        XCTAssertEqual(card.deviceId, Fingerprint.deviceID(approveKey: ak))
        XCTAssertNoThrow(try verifyES256(s.card, x963: ak))
        XCTAssertNoThrow(try verifyES256(s.decision, x963: ak))
    }

    // MARK: negative

    func testTamperedCiphertextRejected() throws {
        let (_, dev, pinned, fixtureListing) = try fixture()
        var listing = fixtureListing
        var ct = try B64.decode(listing.box.ct)
        ct[ct.count / 2] ^= 0x01
        listing.box.ct = B64.encode(ct)
        XCTAssertThrowsError(try dev.open(listing, pinned: pinned))
    }

    func testWrongAdapterKeyRejected() throws {
        let (g, dev, _, listing) = try fixture()
        let wrong = [g.adapterId: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation]
        XCTAssertThrowsError(try dev.open(listing, pinned: wrong)) { err in
            XCTAssertEqual(err as? ProtocolError, .badSignature("adapter \(g.adapterId)"))
        }
        XCTAssertThrowsError(try dev.open(listing, pinned: [:]), "unpinned adapter must be refused")
    }

    func testListingMismatchRejected() throws {
        let (_, dev, pinned, listing) = try fixture()
        var other = listing
        other.id = "interop-2" // the hub relabels a record
        XCTAssertThrowsError(try dev.open(other, pinned: pinned))
    }

    func testBoxForAnotherDeviceRejected() throws {
        let (_, _, pinned, listing) = try fixture()
        let stranger = Device(keys: SoftwareKeyStore(storage: MemoryStorage()))
        try stranger.keys.generate(pin: nil)
        XCTAssertThrowsError(try stranger.open(listing, pinned: pinned))
    }

    /// An ack is checked for its type: the adapter signs records with the same key.
    func testRecordIsNotAnAck() throws {
        let key = Curve25519.Signing.PrivateKey()
        let pinned = ["demo": key.publicKey.rawRepresentation]
        let dev = Device(keys: SoftwareKeyStore(storage: MemoryStorage()))
        func signed(_ json: String) throws -> HubAck {
            let p = Data(json.utf8)
            return HubAck(adapter: "demo", requestId: "r1", ack: Envelope(alg: Envelope.ed25519, kid: "demo",
                payload: B64.encode(p), sig: B64.encode(try key.signature(for: p))))
        }
        let fields = #""v":1,"request_id":"r1","adapter":"demo","outcome":"approved","ts":1}"#
        XCTAssertNoThrow(try dev.verifyAck(try signed(#"{"t":"ack","# + fields), pinned: pinned))
        XCTAssertThrowsError(try dev.verifyAck(try signed(#"{"t":"record","# + fields), pinned: pinned))
        XCTAssertThrowsError(try dev.verifyAck(try signed("{" + fields), pinned: pinned), "untyped")
    }

    func testDeviceNames() throws {
        XCTAssertTrue(isValidDeviceName("Kim\u{2019}s iPhone \u{1F600}"))
        XCTAssertTrue(isValidDeviceName(String(repeating: "n", count: maxDeviceName)))
        for bad in [String(repeating: "n", count: maxDeviceName + 1), "phone\nevil", "phone\u{202E}evil", "phone\u{0085}",
                    "phone\u{2028}", "a\u{200B}b"] {
            XCTAssertFalse(isValidDeviceName(bad), bad.debugDescription)
        }
        XCTAssertEqual(cleanDeviceName("  a\tb\r\nc\u{2028}d  "), "a b c d")
        XCTAssertEqual(cleanDeviceName("x\u{202E}y\u{200B}z\u{0007}\u{0085}"), "xyz")
        XCTAssertEqual(cleanDeviceName(String(repeating: "\u{E9}", count: 60)), String(repeating: "\u{E9}", count: 50))
        XCTAssertEqual(cleanDeviceName(String(repeating: "a", count: 99) + "\u{E9}xx"), String(repeating: "a", count: 99))

        // A card is made with a clean name, and a card with a bad one does not verify.
        let dev = Device(keys: SoftwareKeyStore(storage: MemoryStorage()))
        try dev.keys.generate(pin: nil)
        let card = try verifyCard(try dev.card(name: "phone\u{202E}" + String(repeating: "x", count: 200)))
        XCTAssertEqual(card.name, "phone" + String(repeating: "x", count: maxDeviceName - 5))
        let pk = try dev.keys.publicKeys()
        func signedCard(_ edit: (inout DeviceCard) -> Void) throws -> Envelope {
            var c = DeviceCard(v: protocolVersion, deviceId: pk.deviceID, name: "phone", approveKey: B64.encode(pk.approve),
                               denyKey: B64.encode(pk.deny), encKey: B64.encode(pk.enc), createdAt: 1)
            edit(&c)
            let p = try Coders.encoder.encode(c)
            return Envelope(alg: Envelope.es256, kid: pk.deviceID, payload: B64.encode(p),
                            sig: B64.encode(try dev.keys.signApprove(p, pin: nil)))
        }
        XCTAssertNoThrow(try verifyCard(try signedCard { _ in }))
        XCTAssertThrowsError(try verifyCard(try signedCard { $0.name = "phone\u{202E}" }))
        XCTAssertThrowsError(try verifyCard(try signedCard { $0.name = String(repeating: "n", count: maxDeviceName + 1) }))
        XCTAssertThrowsError(try verifyCard(try signedCard { $0.t = PayloadType.roster }))
    }

    func testSanitize() {
        XCTAssertEqual(sanitize("rotate the \u{201C}certs\u{201D}\u{202E} \u{2014} with\n\tunicode"),
                       "rotate the \u{201C}certs\u{201D} \u{2014} with unicode")
        XCTAssertEqual(sanitize("a\u{200B}b\u{2066}c\u{0007}d"), "abcd") // zero-width space is Cf
        XCTAssertEqual(sanitize("  many   spaces \r\n"), "many spaces")
    }

    func testEnrollmentLink() throws {
        let l = EnrollmentLink("interpose://enroll?hub=http%3A%2F%2F127.0.0.1%3A8740&code=ABC123&user=vince&mode=join")
        XCTAssertEqual(l?.hub.absoluteString, "http://127.0.0.1:8740")
        XCTAssertEqual(l?.code, "ABC123")
        XCTAssertEqual(l?.user, "vince")
        XCTAssertEqual(l?.mode, .join)
        XCTAssertNil(EnrollmentLink("https://evil/enroll?hub=x&code=y&user=v&mode=new"))
        XCTAssertNil(EnrollmentLink("interpose://enroll?hub=file%3A%2F%2F%2Fetc&code=y&user=v&mode=new"))
        XCTAssertThrowsError(try EnrollmentLink(parsing: "interpose://enroll?hub=http%3A%2F%2Fh&code=ABC")) { err in
            XCTAssertEqual(err as? EnrollmentLink.LinkError, .old)
        }
        XCTAssertNil(EnrollmentLink("interpose://enroll?hub=http%3A%2F%2Fh&code=ABC&user=Vince&mode=new"), "user ids are lower-case")
        XCTAssertNil(EnrollmentLink("interpose://enroll?hub=http%3A%2F%2Fh&code=ABC&user=v&mode=admin"))
    }

    func testFingerprint() {
        XCTAssertEqual(Fingerprint.of(Data("abc".utf8)), "ba78-16bf-8f01-cfea")
    }
}
