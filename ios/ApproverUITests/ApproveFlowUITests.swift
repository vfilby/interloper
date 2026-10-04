import XCTest

/// Drives the real app against a live hub and demo adapter (see ios/README.md, "End-to-end UI test").
/// The enrollment link comes from the environment: `TEST_RUNNER_WGA_ENROLL_LINK=wga://enroll?...` on xcodebuild.
/// Expects one normal-risk request titled "claude wants RW on build-01" and one high-risk "helper wants ADMIN on n".
final class ApproveFlowUITests: XCTestCase {
    func testEnrollApproveAndHoldToApprove() throws {
        guard let link = ProcessInfo.processInfo.environment["WGA_ENROLL_LINK"], !link.isEmpty else {
            throw XCTSkip("WGA_ENROLL_LINK not set: needs a running hub")
        }
        let app = XCUIApplication()
        app.launchArguments = ["-wgaAutoEnroll", link]
        app.launch()

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
        let admin = app.staticTexts["helper wants ADMIN on n"]
        XCTAssertTrue(admin.waitForExistence(timeout: 10))
        admin.tap()
        attach(app, "detail-high")
        let hold = app.buttons["Hold to approve"]
        XCTAssertTrue(hold.waitForExistence(timeout: 5))
        hold.tap()
        XCTAssertFalse(app.staticTexts["approved (confirmed by demo)"].waitForExistence(timeout: 3), "a tap approved a high-risk request")
        hold.press(forDuration: 2.5)
        XCTAssertTrue(app.staticTexts["approved (confirmed by demo)"].waitForExistence(timeout: 20), "hold did not approve")
        attach(app, "approved-high")

        // Re-enroll from the Device tab with a second code (same hub: what you do after the hub forgot the device),
        // typing the link as a person would paste it. Then leave the hub.
        guard let link2 = ProcessInfo.processInfo.environment["WGA_ENROLL_LINK2"], !link2.isEmpty else { return }
        app.tabBars.buttons["Device"].tap()
        let another = app.buttons["Enroll with another hub…"]
        XCTAssertTrue(another.waitForExistence(timeout: 5))
        another.tap()
        let field = app.textFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5), "switch-hub sheet did not open")
        field.tap()
        field.typeText(link2)
        attach(app, "switch-hub")
        app.buttons["Enroll with this hub"].tap()
        XCTAssertTrue(app.buttons["Done"].waitForExistence(timeout: 20), "re-enrollment summary did not appear")
        app.buttons["Done"].tap()

        let leave = app.buttons["Leave this hub"]
        XCTAssertTrue(leave.waitForExistence(timeout: 5))
        leave.tap()
        app.buttons["Leave hub"].tap()
        XCTAssertTrue(app.navigationBars["Enroll"].waitForExistence(timeout: 5), "leaving did not return to Enroll")
        attach(app, "left-hub")
    }

    private func attach(_ app: XCUIApplication, _ name: String) {
        let a = XCTAttachment(screenshot: app.screenshot())
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }
}
