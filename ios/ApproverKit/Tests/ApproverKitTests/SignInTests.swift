import XCTest
@testable import ApproverKit

final class SignInTests: XCTestCase {
    func testStartURL() {
        XCTAssertEqual(SignIn.startURL("https://approvals.home.example")?.absoluteString, "https://approvals.home.example/app/enroll")
        XCTAssertEqual(SignIn.startURL("approvals.home.example/")?.absoluteString, "https://approvals.home.example/app/enroll")
        XCTAssertEqual(SignIn.startURL(" http://127.0.0.1:18741/app/enroll?user=vince ")?.absoluteString,
                       "http://127.0.0.1:18741/app/enroll?user=vince")
        XCTAssertNil(SignIn.startURL(""))
        XCTAssertNil(SignIn.startURL("wga://enroll?code=x"))
        XCTAssertNil(SignIn.startURL("javascript:alert(1)"))
        XCTAssertNil(SignIn.startURL("https://"))
    }
}
