import Foundation

/// What an Interloper server says about itself at /app/hello, before anyone signs in.
public struct ServerInfo: Codable, Equatable, Sendable {
    public var service: String
    public var version: Int
    /// "oidc": the person signs in on the server; "local": a development server with no sign-in (the app asks for a
    /// user id instead).
    public var signin: String
    /// The device API, as enrollment links will name it.
    public var api: String
    public var isLocal: Bool { signin == "local" }
}

/// Onboarding: find the Interloper server, then continue on it (sign in there) to get an enrollment link.
public enum SignIn {
    public enum Failure: Error, LocalizedError, Equatable {
        case badAddress
        case notInterloper(String)
        public var errorDescription: String? {
            switch self {
            case .badAddress: return "That is not a server address."
            case .notInterloper(let why): return "No Interloper server there (\(why))."
            }
        }
    }

    /// The server's base URL for an address as typed: "interpose-hub.home.example", "https://interpose-hub.home.example/",
    /// "http://127.0.0.1:18741". Scheme defaults to https; any path is dropped. Only http(s) with a host.
    public static func base(_ address: String) -> URL? {
        var s = address.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return nil }
        if !s.contains("://") { s = "https://" + s }
        guard var c = URLComponents(string: s), let scheme = c.scheme?.lowercased(),
              scheme == "https" || scheme == "http", let host = c.host, !host.isEmpty else { return nil }
        c.scheme = scheme
        c.path = ""
        c.query = nil
        c.fragment = nil
        c.user = nil
        c.password = nil
        return c.url
    }

    /// Asks the server what it is.
    public static func hello(_ base: URL, session: URLSession = .shared) async throws -> ServerInfo {
        var req = URLRequest(url: base.appendingPathComponent("app/hello"))
        req.timeoutInterval = 10
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
            throw Failure.notInterloper("HTTP \((resp as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        guard let info = try? JSONDecoder().decode(ServerInfo.self, from: data), info.service == "interloper" else {
            throw Failure.notInterloper("it does not answer like one")
        }
        return info
    }

    /// Where the person continues on the server: sign in there, and the server answers with an interpose://enroll link.
    /// A local (development) server takes the user id as a parameter instead of a sign-in.
    public static func enrollURL(_ base: URL, user: String? = nil) -> URL {
        var c = URLComponents(url: base.appendingPathComponent("app/enroll"), resolvingAgainstBaseURL: false)!
        if let user, !user.isEmpty {
            c.queryItems = [URLQueryItem(name: "user", value: user.lowercased())]
        }
        return c.url!
    }
}
