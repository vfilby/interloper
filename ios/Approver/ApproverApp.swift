import ApproverKit
import SwiftUI

@main
struct ApproverApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .onOpenURL { url in
                    if let link = EnrollmentLink(url.absoluteString) {
                        model.pendingLink = link
                    } else {
                        model.lastError = "Not an enrollment link: \(url.absoluteString)"
                    }
                }
                #if DEBUG && targetEnvironment(simulator)
                // UI tests: `-wgaAutoEnroll <link>` resets and enrolls without a tap (the simulator keychain outlives an
                // uninstall, so a previous run's enrollment would linger). Simulator debug builds only.
                .task {
                    let args = ProcessInfo.processInfo.arguments
                    if let i = args.firstIndex(of: "-wgaAutoEnroll"), i + 1 < args.count, let link = EnrollmentLink(args[i + 1]) {
                        model.reset()
                        await model.enroll(link, name: "Simulator UI test", pin: nil)
                    }
                }
                #endif
        }
    }
}

struct RootView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            if model.isEnrolled {
                TabView {
                    NavigationStack { InboxView() }
                        .tabItem { Label("Requests", systemImage: "tray") }
                    NavigationStack { SettingsView() }
                        .tabItem { Label("Device", systemImage: "key") }
                }
                .task(id: scenePhase) {
                    // Poll while in the foreground, on every screen (a .task on the inbox would stop when a request
                    // is opened, and its ack would never arrive).
                    guard scenePhase == .active else { return }
                    while !Task.isCancelled {
                        await model.refresh()
                        try? await Task.sleep(for: .seconds(5))
                    }
                }
            } else {
                NavigationStack { EnrollView() }
            }
        }
        .sheet(item: Binding(get: { model.enrollmentSummary.map(SummaryBox.init) }, set: { if $0 == nil { model.enrollmentSummary = nil } })) { box in
            EnrollmentSummaryView(summary: box.summary)
        }
    }
}

private struct SummaryBox: Identifiable {
    let summary: AppModel.EnrollmentSummary
    var id: String { summary.deviceFingerprint }
}

/// Shown on top of every screen when the keys are software keys (the simulator).
struct InsecureBanner: View {
    @EnvironmentObject var model: AppModel

    var body: some View {
        if model.isInsecure {
            Label("Software keys: INSECURE, for testing only. No Secure Enclave on this device.",
                  systemImage: "exclamationmark.triangle.fill")
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.white)
                .padding(8)
                .frame(maxWidth: .infinity)
                .background(Color.orange)
        }
    }
}

extension Fact {
    var color: Color {
        switch level {
        case "danger": return .red
        case "warn": return .orange
        default: return .primary
        }
    }
}
