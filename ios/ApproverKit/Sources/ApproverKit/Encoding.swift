import CryptoKit
import Foundation

/// base64url without padding, as the protocol uses everywhere (docs/PROTOCOL.md "Encodings").
public enum B64 {
    public static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decode(_ s: String) throws -> Data {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        guard let d = Data(base64Encoded: t) else { throw ProtocolError.malformed("not base64url") }
        return d
    }
}

public enum Fingerprint {
    /// First 8 bytes of SHA-256 over a raw public key, as `3f2a-91c0-77de-0b14`.
    public static func of(_ raw: Data) -> String {
        let h = hex(raw)
        return [h.prefix(4), h.dropFirst(4).prefix(4), h.dropFirst(8).prefix(4), h.dropFirst(12).prefix(4)]
            .map(String.init).joined(separator: "-")
    }

    /// Device id: the approve key's fingerprint without dashes.
    public static func deviceID(approveKey raw: Data) -> String { hex(raw) }

    private static func hex(_ raw: Data) -> String {
        SHA256.hash(data: raw).prefix(8).map { String(format: "%02x", $0) }.joined()
    }
}

public func sha256(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

public enum ProtocolError: Error, LocalizedError, Equatable {
    case malformed(String)
    case badSignature(String)
    case mismatch(String)
    case untrusted(String)

    public var errorDescription: String? {
        switch self {
        case .malformed(let s): return "Malformed: \(s)"
        case .badSignature(let s): return "Bad signature: \(s)"
        case .mismatch(let s): return "Mismatch: \(s)"
        case .untrusted(let s): return "Untrusted: \(s)"
        }
    }
}

/// JSON coders matching the Go side's snake_case field names.
enum Coders {
    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }()

    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.keyEncodingStrategy = .convertToSnakeCase
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return e
    }()
}
