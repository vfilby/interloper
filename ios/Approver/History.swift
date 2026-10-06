import ApproverKit
import Foundation

/// A request this device opened, kept after the hub stops listing it so it can be reviewed later: what was asked, what
/// this device decided, and how it ended.
struct HistoryEntry: Codable, Identifiable, Equatable {
    var request: OpenedRequest
    var firstSeen: Date
    /// This device's latest decision (true: approve), if it sent one.
    var approved: Bool?
    var decidedAt: Date?
    /// The verified final ack (approved, denied or expired), whoever decided.
    var settled: Ack?

    var id: String { request.id }
    var record: Record { request.record }
}

/// The history on disk: one JSON file in Application Support, readable only while the phone is unlocked, not backed
/// up. It holds the opened records (host names, reasons), so it is cleared with the hub (leave, reset).
struct HistoryFile {
    /// Oldest entries go first beyond this.
    static let limit = 500

    let url: URL

    init(name: String = "history.json") {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        url = dir.appendingPathComponent(name)
    }

    func load() -> [HistoryEntry] {
        guard let data = try? Data(contentsOf: url) else { return [] }
        return (try? JSONDecoder().decode([HistoryEntry].self, from: data)) ?? []
    }

    func save(_ entries: [HistoryEntry]) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(entries).write(to: url, options: [.atomic, .completeFileProtection])
        var u = url
        var v = URLResourceValues()
        v.isExcludedFromBackup = true
        try u.setResourceValues(v)
    }

    func delete() { try? FileManager.default.removeItem(at: url) }
}
