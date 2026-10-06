import SwiftUI
import UserNotifications

/// APNs. The hub pushes a fixed "Approval request" (or "New device") and nothing else; the app then fetches the
/// sealed request over its usual connection, so a push carries no content to verify or leak.
@MainActor
final class PushDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    weak var model: AppModel? {
        didSet { openTapped() }
    }
    /// The thread of a notification tapped before the model was attached (a launch from the notification).
    private var tapped: String?

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        Task { await model?.registerPush(hex) }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        model?.pushError = error.localizedDescription
    }

    // In the foreground: show it, and fetch at once rather than at the next poll.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification)
        async -> UNNotificationPresentationOptions {
        await refresh()
        return [.banner, .list, .sound]
    }

    // Tapped: open what it is about.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let thread = response.notification.request.content.threadIdentifier
        await tap(thread)
    }

    private func tap(_ thread: String) {
        tapped = thread
        openTapped()
    }

    private func openTapped() {
        guard let model, let thread = tapped, model.isEnrolled else { return }
        tapped = nil
        Task { await model.openFromNotification(thread: thread) }
    }

    private func refresh() async { await model?.refresh() }
}
