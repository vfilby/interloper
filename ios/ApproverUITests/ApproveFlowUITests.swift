import XCTest

/// Drives the real app against a live hub and demo adapter (see ios/README.md, "End-to-end UI test").
/// The hub's management UI comes from the environment: `TEST_RUNNER_WGA_ADMIN_URL=http://127.0.0.1:18741` on
/// xcodebuild. The hub runs without OIDC (local mode), so phone sign-in answers at once for `?user=vince`.
/// Expects one normal-risk request titled "claude wants RW on forge-01" and one high-risk "maggy wants ADMIN on n".
final class ApproveFlowUITests: XCTestCase {
    func testEnrollApproveAndHoldToApprove() throws {
        guard let admin = ProcessInfo.processInfo.environment["WGA_ADMIN_URL"], !admin.isEmpty else {
            throw XCTSkip("WGA_ADMIN_URL not set: needs a running hub")
        }
        let app = XCUIApplication()
        app.launchArguments = ["-wgaReset"]
        app.launch()

        // Step 1: the Interloper server. Return submits, and the app checks the address is one (/app/hello).
        let address = app.textFields["approvals.home.example"]
        XCTAssertTrue(address.waitForExistence(timeout: 10), "the app does not open on the server step")
        attach(app, "server-step")
        address.tap()
        if let old = address.value as? String, !old.isEmpty, old != address.placeholderValue {
            address.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: old.count)) // a remembered address
        }
        address.typeText(admin + "\n")

        // Step 2: continue on the server. This hub is in local mode, so it asks for a user id instead of a sign-in;
        // the app still opens the server in a private browser session and gets the enrollment link back.
        let user = app.textFields["Your user id"]
        XCTAssertTrue(user.waitForExistence(timeout: 10), "the server was not accepted")
        user.tap()
        user.typeText("vince\n")
        let onServer = app.buttons.containing(NSPredicate(format: "label BEGINSWITH 'Continue on'")).firstMatch
        scrollTo(onServer, in: app)
        attach(app, "server-accepted")
        onServer.tap()

        // Step 3: connect this device.
        let newAccount = app.staticTexts.containing(NSPredicate(format: "label CONTAINS 'first device of a new account'")).firstMatch
        XCTAssertTrue(newAccount.waitForExistence(timeout: 20), "the server sent back no enrollment link")
        attach(app, "connect-step")
        let connect = app.buttons["Connect this device"]
        scrollTo(connect, in: app)
        connect.tap()

        let done = app.buttons["Done"]
        XCTAssertTrue(done.waitForExistence(timeout: 20), "enrollment summary did not appear")
        attach(app, "enrolled")
        done.tap()

        // Normal risk: a plain Approve.
        let rw = app.staticTexts["claude wants RW on forge-01"]
        XCTAssertTrue(rw.waitForExistence(timeout: 20), "request not in the inbox")
        attach(app, "inbox")
        rw.tap()
        attach(app, "detail-normal")
        app.buttons["Approve"].tap()
        XCTAssertTrue(app.staticTexts["approved (confirmed by demo)"].waitForExistence(timeout: 20), "no verified ack")
        attach(app, "approved")
        app.navigationBars.buttons.element(boundBy: 0).tap()

        // High risk: a tap is not enough; a long press is.
        let adminRequest = app.staticTexts["maggy wants ADMIN on n"]
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
        let another = app.buttons["Connect to another server…"]
        scrollTo(another, in: app) // below the Account section; SwiftUI lists load rows lazily
        another.tap()
        let useLink = app.buttons["I have an enrollment link or QR code"]
        XCTAssertTrue(useLink.waitForExistence(timeout: 5), "connect sheet did not open on the server step")
        useLink.tap()
        let field = app.textFields["wga://enroll?hub=…&code=…"]
        XCTAssertTrue(field.waitForExistence(timeout: 5), "no link field")
        field.tap()
        field.typeText(link2)
        attach(app, "switch-hub")
        let connectHere = app.buttons["Connect this device"]
        scrollTo(connectHere, in: app) // the keyboard covers the lower half of the sheet
        connectHere.tap()
        XCTAssertTrue(app.buttons["Done"].waitForExistence(timeout: 20), "re-enrollment summary did not appear")
        app.buttons["Done"].tap()

        let leave = app.buttons["Leave this hub"]
        scrollTo(leave, in: app)
        leave.tap()
        app.buttons["Leave hub"].tap()
        XCTAssertTrue(app.textFields["approvals.home.example"].waitForExistence(timeout: 5), "leaving did not return to the server step")
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
