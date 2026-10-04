import Foundation

/// Phone sign-in: where the app sends the person to sign in so the hub hands back an enrollment link.
public enum SignIn {
    /// The URL to open for an address typed by the person. A bare management address ("https://approvals.home.example")
    /// gets the hub's phone sign-in path; an address with its own path is used as typed (a hub in local mode on a
    /// development machine takes `…/app/enroll?user=<id>`). Only http(s) with a host.
    public static func startURL(_ address: String) -> URL? {
        var s = address.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return nil }
        if !s.contains("://") { s = "https://" + s }
        guard var c = URLComponents(string: s), let scheme = c.scheme?.lowercased(),
              scheme == "https" || scheme == "http", let host = c.host, !host.isEmpty else { return nil }
        if c.path.isEmpty || c.path == "/" {
            c.path = "/app/enroll"
        }
        return c.url
    }
}
