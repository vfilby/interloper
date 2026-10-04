import Foundation

/// The hub's device API (docs/PROTOCOL.md "Hub HTTP API"). The hub is transport: nothing it returns is trusted
/// until `Device` has verified it.
public struct HubClient: Sendable {
    public let base: URL
    public let token: String?
    private let session: URLSession

    public init(base: URL, token: String?, session: URLSession = .shared) {
        self.base = base
        self.token = token
        self.session = session
    }

    public enum HubError: Error, LocalizedError {
        case http(Int, String)
        public var errorDescription: String? {
            switch self { case .http(let c, let b): return "Hub answered HTTP \(c): \(b)" }
        }
    }

    public func enroll(code: String, card: Envelope) async throws -> EnrollResponse {
        let d = try await call("POST", "/v1/enroll", body: try Coders.encoder.encode(EnrollRequest(code: code, card: card)), auth: false)
        return try Coders.decoder.decode(EnrollResponse.self, from: d)
    }

    public func adapters() async throws -> [HubAdapter] { try list(await call("GET", "/v1/device/adapters")) }

    public func requests() async throws -> [HubRequest] { try list(await call("GET", "/v1/device/requests")) }

    public func acks(since: Int64) async throws -> [HubAck] { try list(await call("GET", "/v1/device/acks?since=\(since)")) }

    public func postDecision(_ d: DecisionPost) async throws {
        _ = try await call("POST", "/v1/device/decisions", body: try Coders.encoder.encode(d))
    }

    /// Go encodes an empty slice as null; both mean "none".
    private func list<T: Decodable>(_ data: Data) throws -> [T] {
        if data.isEmpty { return [] }
        return try Coders.decoder.decode([T]?.self, from: data) ?? []
    }

    private func call(_ method: String, _ path: String, body: Data? = nil, auth: Bool = true) async throws -> Data {
        // Appended, not resolved: a hub published under a path prefix keeps it.
        var root = base.absoluteString
        while root.hasSuffix("/") { root.removeLast() }
        guard let url = URL(string: root + path) else { throw HubError.http(0, "bad path \(path)") }
        var req = URLRequest(url: url, timeoutInterval: 20)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        if auth, let token { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if let body {
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(code) else {
            throw HubError.http(code, String(decoding: data.prefix(300), as: UTF8.self))
        }
        return data
    }
}
