import Foundation
import XCTest
@testable import ApproverKit

/// Pins: adapter keys the hub lists are only offered until confirmed, and pins live in SecretStorage (the Keychain).
final class PinsTests: XCTestCase {
    func key(_ b: UInt8) -> Data { Data(repeating: b, count: 32) }
    func listed(_ id: String, _ k: Data) -> HubAdapter { HubAdapter(id: id, key: B64.encode(k), fingerprint: "ignored") }

    func testNewAdapterKeysAreOfferedNotPinned() {
        let (offered, conflicts) = sortAdapters([listed("b", key(2)), listed("a", key(1))], pinned: [])
        XCTAssertEqual(offered, [PinnedAdapter(id: "a", key: key(1)), PinnedAdapter(id: "b", key: key(2))])
        XCTAssertEqual(conflicts, [])
    }

    func testPinnedKeyIsKeptAndAChangedOneIsAConflict() {
        let pinned = [PinnedAdapter(id: "a", key: key(1)), PinnedAdapter(id: "b", key: key(2))]
        let (offered, conflicts) = sortAdapters([listed("a", key(1)), listed("b", key(9))], pinned: pinned)
        XCTAssertEqual(offered, [])
        XCTAssertEqual(conflicts, [AdapterConflict(id: "b", pinned: Fingerprint.of(key(2)), offered: Fingerprint.of(key(9)))])
    }

    func testBadKeysAndDuplicateIdsAreNotOffered() {
        let (offered, _) = sortAdapters([listed("short", Data(repeating: 1, count: 31)),
                                         HubAdapter(id: "junk", key: "%%%", fingerprint: ""),
                                         listed("a", key(1)), listed("a", key(2))], pinned: [])
        XCTAssertEqual(offered, [PinnedAdapter(id: "a", key: key(1))])
    }

    func testStoreRoundTripsAndClears() throws {
        let s = PinStore(storage: MemoryStorage())
        XCTAssertNil(try s.load(.account, as: String.self))
        try s.save(.account, "3f2a-91c0-77de-0b14-5c2e-aa01-9d3b-71f0")
        try s.save(.adapters, [PinnedAdapter(id: "a", key: key(1))])
        try s.save(.knownHead, KnownHead(seq: 3, payloadHash: "h"))
        XCTAssertEqual(try s.load(.account, as: String.self), "3f2a-91c0-77de-0b14-5c2e-aa01-9d3b-71f0")
        XCTAssertEqual(try s.load(.adapters, as: [PinnedAdapter].self), [PinnedAdapter(id: "a", key: key(1))])
        XCTAssertEqual(try s.load(.knownHead, as: KnownHead.self), KnownHead(seq: 3, payloadHash: "h"))
        try s.save(.account, String?.none)
        XCTAssertNil(try s.load(.account, as: String.self))
        try s.clear()
        XCTAssertNil(try s.load(.adapters, as: [PinnedAdapter].self))
        XCTAssertNil(try s.load(.knownHead, as: KnownHead.self))
    }

    func testMigratesPinsOutOfUserDefaults() throws {
        let name = "PinsTests-\(UUID())"
        let d = try XCTUnwrap(UserDefaults(suiteName: name))
        defer { d.removePersistentDomain(forName: name) }
        d.set("acct", forKey: "account")
        d.set(["a": B64.encode(key(1))], forKey: "pinnedAdapters")
        d.set(try JSONEncoder().encode(KnownHead(seq: 2, payloadHash: "h")), forKey: "knownHead")

        let s = PinStore(storage: MemoryStorage())
        try s.migrate(from: d)
        XCTAssertEqual(try s.load(.account, as: String.self), "acct")
        XCTAssertEqual(try s.load(.adapters, as: [PinnedAdapter].self), [PinnedAdapter(id: "a", key: key(1))])
        XCTAssertEqual(try s.load(.knownHead, as: KnownHead.self), KnownHead(seq: 2, payloadHash: "h"))
        XCTAssertNil(d.object(forKey: "account"))
        XCTAssertNil(d.object(forKey: "pinnedAdapters"))
        XCTAssertNil(d.object(forKey: "knownHead"))
    }

    func testMigrationNeverOverwritesAKeychainPin() throws {
        let name = "PinsTests-\(UUID())"
        let d = try XCTUnwrap(UserDefaults(suiteName: name))
        defer { d.removePersistentDomain(forName: name) }
        let s = PinStore(storage: MemoryStorage())
        try s.save(.account, "keychain")
        d.set("defaults", forKey: "account")
        try s.migrate(from: d)
        XCTAssertEqual(try s.load(.account, as: String.self), "keychain")
        XCTAssertNil(d.object(forKey: "account"))
    }
}
