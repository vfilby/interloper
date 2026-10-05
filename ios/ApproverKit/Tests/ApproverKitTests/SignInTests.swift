import XCTest
@testable import ApproverKit

final class SignInTests: XCTestCase {
    func testBase() {
        XCTAssertEqual(SignIn.base("interpose-hub.home.example")?.absoluteString, "https://interpose-hub.home.example")
        XCTAssertEqual(SignIn.base(" https://interpose-hub.home.example/some/path?x=1 ")?.absoluteString, "https://interpose-hub.home.example")
        XCTAssertEqual(SignIn.base("http://127.0.0.1:18741")?.absoluteString, "http://127.0.0.1:18741")
        XCTAssertEqual(SignIn.base("HTTPS://user:pw@interpose-hub.home.example")?.absoluteString, "https://interpose-hub.home.example")
        XCTAssertNil(SignIn.base(""))
        XCTAssertNil(SignIn.base("interpose://enroll?code=x"))
        XCTAssertNil(SignIn.base("javascript:alert(1)"))
        XCTAssertNil(SignIn.base("https://"))
    }

    func testEnrollURL() {
        let base = SignIn.base("https://interpose-hub.home.example")!
        XCTAssertEqual(SignIn.enrollURL(base).absoluteString, "https://interpose-hub.home.example/app/enroll")
        XCTAssertEqual(SignIn.enrollURL(SignIn.base("http://127.0.0.1:18741")!, user: "Vince").absoluteString,
                       "http://127.0.0.1:18741/app/enroll?user=vince")
    }

    func testServerInfoDecodes() throws {
        let info = try JSONDecoder().decode(ServerInfo.self, from: Data(#"{"service":"interloper","version":1,"signin":"local","api":"http://127.0.0.1:8740"}"#.utf8))
        XCTAssertTrue(info.isLocal)
        XCTAssertEqual(info.api, "http://127.0.0.1:8740")
    }
}
