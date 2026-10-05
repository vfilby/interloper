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

        let approve = try dev.decide(opened, approve: true)
        let p = try verifyES256(approve, x963: pk.approve)
        let d = try Coders.decoder.decode(Decision.self, from: p)
        XCTAssertEqual(d.decision, Decision.approve)
        XCTAssertEqual(d.recordHash, B64.encode(sha256(try B64.decode(g.recordPayload))))
        XCTAssertEqual(d.nonce, opened.record.nonce)
        XCTAssertEqual(d.deviceId, pk.deviceID)

        let deny = try dev.decide(opened, approve: false)
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
    /// TestSwiftDecision. Run after the Go side rewrote go-sealed.json: WGA_WRITE_FIXTURE=1 swift test.
    func testWriteSwiftDecision() throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["WGA_WRITE_FIXTURE"] == "1",
                          "set WGA_WRITE_FIXTURE=1 to rewrite internal/protocol/testdata/interop/swift-decision.json")
        let (g, dev, pinned, listing) = try fixture()
        let opened = try dev.open(listing, pinned: pinned)
        // Made at the record's own time, so Go can judge it then, however old the fixture is.
        let at = Date(timeIntervalSince1970: TimeInterval(g.now + 60))
        let out = SwiftDecision(card: try dev.card(name: "swift fixture"), decision: try dev.decide(opened, approve: true, now: at))
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

    func testSanitize() {
        XCTAssertEqual(sanitize("rotate the \u{201C}certs\u{201D}\u{202E} \u{2014} with\n\tunicode"),
                       "rotate the \u{201C}certs\u{201D} \u{2014} with unicode")
        XCTAssertEqual(sanitize("a\u{200B}b\u{2066}c\u{0007}d"), "abcd") // zero-width space is Cf
        XCTAssertEqual(sanitize("  many   spaces \r\n"), "many spaces")
    }

    func testEnrollmentLink() throws {
        let l = EnrollmentLink("wga://enroll?hub=http%3A%2F%2F127.0.0.1%3A8740&code=ABC123&user=vince&mode=join")
        XCTAssertEqual(l?.hub.absoluteString, "http://127.0.0.1:8740")
        XCTAssertEqual(l?.code, "ABC123")
        XCTAssertEqual(l?.user, "vince")
        XCTAssertEqual(l?.mode, .join)
        XCTAssertNil(EnrollmentLink("https://evil/enroll?hub=x&code=y&user=v&mode=new"))
        XCTAssertNil(EnrollmentLink("wga://enroll?hub=file%3A%2F%2F%2Fetc&code=y&user=v&mode=new"))
        XCTAssertThrowsError(try EnrollmentLink(parsing: "wga://enroll?hub=http%3A%2F%2Fh&code=ABC")) { err in
            XCTAssertEqual(err as? EnrollmentLink.LinkError, .old)
        }
        XCTAssertNil(EnrollmentLink("wga://enroll?hub=http%3A%2F%2Fh&code=ABC&user=Vince&mode=new"), "user ids are lower-case")
        XCTAssertNil(EnrollmentLink("wga://enroll?hub=http%3A%2F%2Fh&code=ABC&user=v&mode=admin"))
    }

    func testFingerprint() {
        XCTAssertEqual(Fingerprint.of(Data("abc".utf8)), "ba78-16bf-8f01-cfea")
    }
}
