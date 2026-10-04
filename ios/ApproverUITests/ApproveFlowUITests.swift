import XCTest

/// Drives the real app against a live hub and demo adapter (see ios/README.md, "End-to-end UI test").
/// The hub's management UI comes from the environment: `TEST_RUNNER_WGA_ADMIN_URL=http://127.0.0.1:18741` on
/// xcodebuild. The hub runs without OIDC (local mode), so phone sign-in answers at once for `?user=vince`.
/// Expects one normal-risk request titled "claude wants RW on build-01" and one high-risk "helper wants ADMIN on n".
final class ApproveFlowUITests: XCTestCase {
    func testEnrollApproveAndHoldToApprove() throws {
        guard let admin = ProcessInfo.processInfo.environment["WGA_ADMIN_URL"], !admin.isEmpty else {
            throw XCTSkip("WGA_ADMIN_URL not set: needs a running hub")
        }
        let app = XCUIApplication()
        app.launchArguments = ["-wgaReset"]
        app.launch()

        // Phone sign-in: the app opens the hub's sign-in in a private browser session and gets a code back.
        let address = app.textFields["https://approvals.home.example"]
        XCTAssertTrue(address.waitForExistence(timeout: 10), "no sign-in address field on the Enroll screen")
        address.tap()
        if let old = address.value as? String, !old.isEmpty, old != address.placeholderValue {
            address.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: old.count)) // a remembered address
        }
        address.typeText(admin + "/app/enroll?user=vince\n") // Return closes the keyboard, which otherwise covers the form
        let signIn = app.buttons["Sign in to get a code"]
        scrollTo(signIn, in: app)
        signIn.tap()
        let newAccount = app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'first device of a new account'")).firstMatch
        XCTAssertTrue(newAccount.waitForExistence(timeout: 20), "sign-in brought back no code")
        attach(app, "signed-in")
        let enroll = app.buttons["Enroll"]
        scrollTo(enroll, in: app)
        enroll.tap()

        let done = app.buttons["Done"]
        XCTAssertTrue(done.waitForExistence(timeout: 20), "enrollment summary did not appear")
        attach(app, "enrolled")
        done.tap()

        // Normal risk: a plain Approve.
        let rw = app.staticTexts["claude wants RW on build-01"]
        XCTAssertTrue(rw.waitForExistence(timeout: 20), "request not in the inbox")
        attach(app, "inbox")
        rw.tap()
        attach(app, "detail-normal")
        app.buttons["Approve"].tap()
        XCTAssertTrue(app.staticTexts["approved (confirmed by demo)"].waitForExistence(timeout: 20), "no verified ack")
        attach(app, "approved")
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // High risk: a tap is not enough; a long press is.
        let adminRequest = app.staticTexts["helper wants ADMIN on n"]
        XCTAssertTrue(adminRequest.waitForExistence(timeout: 10))
        adminRequest.tap()
        attach(app, "detail-high")
        let hold = app.buttons["Hold to approve"]
        XCTAssertTrue(hold.waitForExistence(timeout: 5))
        hold.tap()
        XCTAssertFalse(app.staticTexts["approved (confirmed by demo)"].waitForExistence(timeout: 3), "a tap approved a high-risk request")
        hold.press(forDuration: 2.5)
        XCTAssertTrue(app.staticTexts["approved (confirmed by demo)"].waitForExistence(timeout: 20), "hold did not approve")
        attach(app, "approved-high")

        // Re-enroll from the Device tab with a join code for vince (same hub: what you do after leaving it, or after the
        // hub forgot the device). This phone is already on vince's roster, so it comes back active at once. The code
        // can only exist now that vince does, so the test asks the management UI for it, as an admin would.
        // Typed in as a person would paste it. Then leave the hub.
        let link2 = try joinLink(admin: admin, user: "vince")
        app.tabBars.buttons["Device"].tap()
        let another = app.buttons["Enroll with another hub…"]
        scrollTo(another, in: app) // below the Account section; SwiftUI lists load rows lazily
        another.tap()
        let field = app.textFields["wga://enroll?hub=…&code=…"] // the link field, not the sign-in address above it
        XCTAssertTrue(field.waitForExistence(timeout: 5), "switch-hub sheet did not open")
        field.tap()
        field.typeText(link2)
        attach(app, "switch-hub")
        let enrollHere = app.buttons["Enroll with this hub"]
        scrollTo(enrollHere, in: app) // the keyboard covers the lower half of the sheet
        enrollHere.tap()
        XCTAssertTrue(app.buttons["Done"].waitForExistence(timeout: 20), "re-enrollment summary did not appear")
        app.buttons["Done"].tap()

        let leave = app.buttons["Leave this hub"]
        scrollTo(leave, in: app)
        leave.tap()
        app.buttons["Leave hub"].tap()
        XCTAssertTrue(app.navigationBars["Enroll"].waitForExistence(timeout: 5), "leaving did not return to Enroll")
        attach(app, "left-hub")
    }

    private func scrollTo(_ element: XCUIElement, in app: XCUIApplication) {
        for _ in 0..<6 where !(element.exists && element.isHittable) {
            app.swipeUp()
        }
        XCTAssertTrue(element.waitForExistence(timeout: 3), "\(element) not found after scrolling")
    }

    /// Posts the overview's "Add a device for <user>" form and reads the enrollment link off the page it redirects to.
    private func joinLink(admin: String, user: String) throws -> String {
        var req = URLRequest(url: URL(string: admin + "/enroll")!)
        req.httpMethod = "POST"
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        req.setValue("same-origin", forHTTPHeaderField: "Sec-Fetch-Site")
        req.httpBody = Data("user=\(user)&mode=join".utf8)
        var html = ""
        let done = expectation(description: "join code")
        URLSession.shared.dataTask(with: req) { data, _, _ in
            html = data.map { String(decoding: $0, as: UTF8.self) } ?? ""
            done.fulfill()
        }.resume()
        wait(for: [done], timeout: 10)
        guard let r = html.range(of: #"wga://enroll[^<"']*"#, options: .regularExpression) else {
            XCTFail("no enrollment link in the management UI's page:\n\(html.prefix(500))")
            throw URLError(.cannotParseResponse)
        }
        return html[r].replacingOccurrences(of: "&amp;", with: "&")
    }

    private func attach(_ app: XCUIApplication, _ name: String) {
        let a = XCTAttachment(screenshot: app.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }
}
