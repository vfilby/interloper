import Foundation

/// Which hub addresses the app talks to, and how. Over plain http the one-time code, the device's bearer token and the
/// adapter keys offered for pinning cross the network readable and changeable, and ATS does not police IP-literal
/// hosts. So https only, except http to this machine's loopback when `allowLoopbackHTTP` (Debug builds: the simulator
/// against a hub on the Mac).
public enum HubTransport {
    public enum Refusal: Error, LocalizedError, Equatable {
        case cleartext(String)
        case notHTTP
        public var errorDescription: String? {
            switch self {
            case .cleartext(let url):
                return "\(sanitize(url)) is plain http: the enrollment code, this device's token and the adapter keys would cross the network unencrypted. Use the server's https address."
            case .notHTTP:
                return "Not an http(s) address."
            }
        }
    }

    /// The largest response the app reads from a hub (or a server it checks): enough for many requests, small enough
    /// that a hostile hub cannot exhaust memory.
    public static let maxResponseBytes = 4 << 20

    public static func isCleartext(_ url: URL) -> Bool { url.scheme?.lowercased() == "http" }

    /// localhost, 127.0.0.0/8, ::1.
    public static func isLoopback(_ url: URL) -> Bool {
        guard var host = url.host(percentEncoded: false)?.lowercased() else { return false }
        if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        if host == "localhost" || host == "::1" || host == "0:0:0:0:0:0:0:1" { return true }
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4, parts.allSatisfy({ UInt8($0) != nil }) else { return false }
        return parts[0] == "127"
    }

    /// Throws unless the app may talk to `url`: https, or http to loopback when `allowLoopbackHTTP`.
    public static func check(_ url: URL, allowLoopbackHTTP: Bool) throws {
        switch url.scheme?.lowercased() {
        case "https": return
        case "http":
            if allowLoopbackHTTP && isLoopback(url) { return }
            throw Refusal.cleartext(url.absoluteString)
        default:
            throw Refusal.notHTTP
        }
    }

    /// Whether two addresses name the same host (scheme and port aside).
    public static func sameHost(_ a: URL, _ b: URL) -> Bool {
        guard let ha = a.host(percentEncoded: false)?.lowercased(), let hb = b.host(percentEncoded: false)?.lowercased(),
              !ha.isEmpty else { return false }
        return ha == hb
    }

    public struct TooLarge: Error, LocalizedError {
        public var errorDescription: String? { "The server's answer is larger than \(maxResponseBytes >> 20) MiB: not read." }
    }

    /// One request, without following redirects (a redirect to another host would carry the Authorization header
    /// there) and reading at most `limit` bytes. A redirect comes back as its own 3xx response.
    static func fetch(_ req: URLRequest, session: URLSession, limit: Int = maxResponseBytes) async throws -> (Data, Int) {
        let (bytes, resp) = try await session.bytes(for: req, delegate: NoRedirects())
        if resp.expectedContentLength > Int64(limit) {
            bytes.task.cancel()
            throw TooLarge()
        }
        var data = Data()
        if resp.expectedContentLength > 0 { data.reserveCapacity(Int(resp.expectedContentLength)) }
        for try await b in bytes {
            data.append(b)
            if data.count > limit {
                bytes.task.cancel()
                throw TooLarge()
            }
        }
        return (data, (resp as? HTTPURLResponse)?.statusCode ?? 0)
    }
}

private final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest) async -> URLRequest? {
        nil
    }
}
