import XCTest
@testable import ApproverKit

final class SignInTests: XCTestCase {
    func testBase() {
        XCTAssertEqual(SignIn.base("approvals.home.example")?.absoluteString, "https://approvals.home.example")
        XCTAssertEqual(SignIn.base(" https://approvals.home.example/some/path?x=1 ")?.absoluteString, "https://approvals.home.example")
        XCTAssertEqual(SignIn.base("http://127.0.0.1:18741")?.absoluteString, "http://127.0.0.1:18741")
        XCTAssertEqual(SignIn.base("HTTPS://user:pw@approvals.home.example")?.absoluteString, "https://approvals.home.example")
        XCTAssertNil(SignIn.base(""))
        XCTAssertNil(SignIn.base("wga://enroll?code=x"))
        XCTAssertNil(SignIn.base("javascript:alert(1)"))
        XCTAssertNil(SignIn.base("https://"))
    }

    func testEnrollURL() {
        let base = SignIn.base("https://approvals.home.example")!
        XCTAssertEqual(SignIn.enrollURL(base).absoluteString, "https://approvals.home.example/app/enroll")
        XCTAssertEqual(SignIn.enrollURL(SignIn.base("http://127.0.0.1:18741")!, user: "Vince").absoluteString,
                       "http://127.0.0.1:18741/app/enroll?user=vince")
    }

    func testServerInfoDecodes() throws {
        let info = try JSONDecoder().decode(ServerInfo.self, from: Data(#"{"service":"interloper","version":1,"signin":"local","api":"http://127.0.0.1:8740"}"#.utf8))
        XCTAssertTrue(info.isLocal)
        XCTAssertEqual(info.api, "http://127.0.0.1:8740")
    }
}
