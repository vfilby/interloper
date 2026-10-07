import CryptoKit
import Foundation
import XCTest
@testable import ApproverKit

/// Rosters: interop with Go (internal/protocol/testdata/interop/go-roster.json, swift-roster.json) and the same attack cases as
/// broker/internal/protocol/roster_test.go.
final class RosterTests: XCTestCase {
    struct GoRoster: Decodable {
        var user: String
        var account: String
        var chain: [Envelope]
        var deviceA: String
        var deviceB: String
    }

    func load<T: Decodable>(_ name: String) throws -> T {
        try Coders.decoder.decode(T.self, from: Data(contentsOf: InteropTests.interopDir.appendingPathComponent(name)))
    }

    /// Device A of go-roster.json is go-sealed.json's device.
    func deviceA() throws -> Device {
        let g: InteropTests.GoSealed = try load("go-sealed.json")
        return Device(keys: try SoftwareKeyStore(approveRaw: B64.decode(g.deviceApproveRaw),
                                                 denyRaw: B64.decode(g.deviceDenyRaw), encRaw: B64.decode(g.deviceEncRaw)))
    }

    func newDevice(_ name: String) throws -> (Device, Envelope) {
        let d = Device(keys: SoftwareKeyStore(storage: MemoryStorage()))
        try d.keys.generate(pin: nil)
        return (d, try d.card(name: name))
    }

    func testGoChainVerifiesAndSwiftExtendsIt() throws {
        let g: GoRoster = try load("go-roster.json")
        let head = try verifyChain(g.chain, user: g.user, account: g.account)
        XCTAssertEqual(head.roster.seq, 2)
        XCTAssertEqual(Set(head.devices.keys), [g.deviceA, g.deviceB])

        let a = try deviceA()
        XCTAssertEqual(try a.deviceID(), g.deviceA)
        let r3 = try a.remove(g.deviceB, after: head)
        let h3 = try extend(head, r3)
        XCTAssertEqual(h3.roster.seq, 3)
        XCTAssertEqual(Array(h3.devices.keys), [g.deviceA])
        let chain = g.chain + [r3]
        XCTAssertNoThrow(try verifyChain(chain, user: g.user, account: g.account))

        // For Go's TestSwiftRoster; rewritten only on request, like swift-decision.json.
        if ProcessInfo.processInfo.environment["INTERPOSE_WRITE_FIXTURE"] == "1" {
            let out = try Coders.encoder.encode(["chain": chain])
            try out.write(to: InteropTests.interopDir.appendingPathComponent("swift-roster.json"))
        }
    }

    func testAccountFingerprintShape() throws {
        let g: GoRoster = try load("go-roster.json")
        XCTAssertEqual(accountFingerprint(genesisPayload: try B64.decode(g.chain[0].payload)), g.account)
        XCTAssertEqual(g.account.split(separator: "-").count, 8)
    }

    /// A removed device still has its key: it forks from the last roster it was on. The fork verifies from genesis
    /// and is longer, so only "build on what you already accepted" stops it.
    /// The hub's JSON for GET /v1/device/joins and the enroll response, as Go writes them.
    func testDecodesHubJoinAndEnrollJSON() throws {
        let joins = try Coders.decoder.decode([HubJoin].self, from: Data("""
        [{"device_id":"8ae71db2c8c403c5","name":"iPhone","card":{"alg":"es256","kid":"8ae71db2c8c403c5","payload":"e30","sig":"AA"},"requested_at":1790000000}]
        """.utf8))
        XCTAssertEqual(joins.first?.requestedAt, 1_790_000_000)
        let enrolled = try Coders.decoder.decode(EnrollResponse.self, from: Data("""
        {"device_id":"8ae71db2c8c403c5","token":"t","user":"vince","status":"pending"}
        """.utf8))
        XCTAssertEqual(enrolled.status, "pending")
        XCTAssertEqual(enrolled.user, "vince")
    }

    func testForkByRemovedDeviceRejected() throws {
        let (a, cardA) = try newDevice("A")
        let (b, cardB) = try newDevice("B")
        let (_, cardM) = try newDevice("mallory")
        let r1 = try a.genesis(user: "vince", card: cardA)
        let h1 = try verifyChain([r1], user: "vince", account: nil)
        let r2 = try a.admit(cardB, after: h1)                 // v2: A, B
        let h2 = try extend(h1, r2)
        let r3 = try b.remove(try a.deviceID(), after: h2)      // v3: B removes A
        let h3 = try extend(h2, r3)
        let known = KnownHead(h3)                               // this device accepted v3

        let alt3 = try a.admit(cardM, after: h2)                // A forks from v2: v3' adds mallory
        let altH3 = try extend(h2, alt3)
        let alt4 = try a.remove(try b.deviceID(), after: altH3) // v4': and drops B
        let fork = [r1, r2, alt3, alt4]
        XCTAssertNoThrow(try verifyChain(fork, user: "vince", account: h1.account), "the fork is valid on its own")
        XCTAssertThrowsError(try requireBuildsOn(fork, known: known)) { err in
            XCTAssertTrue(err.localizedDescription.contains("does not build on"), err.localizedDescription)
        }
        // Same seq, different roster: also refused.
        XCTAssertThrowsError(try requireBuildsOn([r1, r2, alt3], known: known))
        // Rollback: refused.
        XCTAssertThrowsError(try requireBuildsOn([r1, r2], known: known))
        // The honest chain, and its continuation, pass.
        XCTAssertNoThrow(try requireBuildsOn([r1, r2, r3], known: known))
        let (_, cardC) = try newDevice("C")
        let r4 = try b.admit(cardC, after: h3)
        XCTAssertNoThrow(try requireBuildsOn([r1, r2, r3, r4], known: known))
    }

    func testLocalChainAndAttacks() throws {
        let (a, cardA) = try newDevice("A")
        let (b, cardB) = try newDevice("B")
        let (mallory, cardM) = try newDevice("mallory")
        let r1 = try a.genesis(user: "vince", card: cardA)
        let h1 = try verifyChain([r1], user: "vince", account: nil)
        let pin = h1.account
        let r2 = try a.admit(cardB, after: h1)
        let h2 = try extend(h1, r2)
        let r3 = try b.remove(try a.deviceID(), after: h2) // B removes A
        let h3 = try verifyChain([r1, r2, r3], user: "vince", account: pin)
        XCTAssertEqual(Array(h3.devices.keys), [try b.deviceID()])

        // A, removed, cannot sign the next roster.
        XCTAssertThrowsError(try extend(h3, try a.admit(cardM, after: h3)))
        // The last device cannot be removed.
        XCTAssertThrowsError(try b.remove(try b.deviceID(), after: h3))

        func expectFail(_ name: String, _ chain: [Envelope], user: String = "vince", account: String? = nil,
                        _ fragment: String) {
            XCTAssertThrowsError(try verifyChain(chain, user: user, account: account ?? pin), name) { err in
                XCTAssertTrue(err.localizedDescription.contains(fragment), "\(name): \(err.localizedDescription)")
            }
        }
        expectFail("wrong pin", [r1, r2], account: "0000-0000-0000-0000-0000-0000-0000-0000", "does not match")
        expectFail("wrong user", [r1, r2], user: "kim", "this user")
        expectFail("another genesis", [try mallory.genesis(user: "vince", card: cardM)], "does not match")
        expectFail("self-admission", [r1, try mallory.admit(cardM, after: h1)], "not a member")
        expectFail("skipped roster", [r1, r3], "not a member")
        expectFail("replayed roster", [r1, r2, r2], "seq")

        var wrongPrev = nextRoster(after: h1, members: h1.cards)
        wrongPrev.prev = B64.encode(Data("nope".utf8))
        expectFail("wrong prev", [r1, try a.sign(wrongPrev, reason: "test")], "does not follow")

        expectFail("device twice", [r1, try a.sign(nextRoster(after: h1, members: h1.cards + h1.cards), reason: "test")], "twice")

        var unknown = nextRoster(after: h1, members: h1.cards)
        unknown.members[0].kind = "recovery"
        expectFail("unknown kind", [r1, try a.sign(unknown, reason: "test")], "unknown member kind")

        // A member card whose encryption key was swapped (requests redirected): the card no longer verifies.
        var tampered = nextRoster(after: h1, members: h1.cards + [cardB])
        var cc = try Coders.decoder.decode(DeviceCard.self, from: B64.decode(cardB.payload))
        cc.encKey = B64.encode(P256.KeyAgreement.PrivateKey().publicKey.x963Representation)
        tampered.members[1].card.payload = B64.encode(try Coders.encoder.encode(cc))
        expectFail("tampered card", [r1, try a.sign(tampered, reason: "test")], "card")
    }

    /// The hub reads `delete_account` and `roster`, and treats a missing field as "no".
    func testLeavePostWireFormat() throws {
        let plain = String(decoding: try Coders.encoder.encode(LeavePost()), as: UTF8.self)
        XCTAssertEqual(plain, "{}")
        let last = String(decoding: try Coders.encoder.encode(LeavePost(deleteAccount: true)), as: UTF8.self)
        XCTAssertEqual(last, #"{"delete_account":true}"#)
    }
}
