import ApproverKit
import SwiftUI

@main
struct ApproverApp: App {
    @StateObject private var model = AppModel()
    @UIApplicationDelegateAdaptor(PushDelegate.self) private var push

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .onAppear { push.model = model }
                .onOpenURL { url in
                    do {
                        model.pendingLink = try EnrollmentLink(parsing: url.absoluteString)
                        // Already enrolled: offer to move to that hub (or re-enroll at this one) instead of ignoring it.
                        if model.isEnrolled { model.sheet = .switchHub }
                    } catch {
                        model.lastError = error.localizedDescription
                    }
                }
                #if DEBUG && targetEnvironment(simulator)
                // UI tests: `-interposeReset` starts from nothing (the simulator keychain outlives an uninstall, so a
                // previous run's enrollment would linger); `-interposeAutoEnroll <link>` also enrolls without a tap.
                // Simulator debug builds only.
                .task {
                    let args = ProcessInfo.processInfo.arguments
                    if args.contains("-interposeReset") {
                        model.forgetLocally(deleteKeys: true)
                        UserDefaults.standard.removeObject(forKey: "signInAddress")
                    }
                    if let i = args.firstIndex(of: "-interposeAutoEnroll"), i + 1 < args.count, let link = EnrollmentLink(args[i + 1]) {
                        model.forgetLocally(deleteKeys: true)
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
                .task { await model.enablePush() }
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
        .pinPrompt()
        .privacyCover()
        .sheet(item: $model.sheet, onDismiss: {
            // Cancelled a hub switch: drop the link it came with. (A finished one has already cleared it.)
            if model.sheet == nil { model.pendingLink = nil }
        }) { sheet in
            switch sheet {
            case .switchHub:
                NavigationStack { EnrollView(switching: true) }.pinPrompt().privacyCover().environmentObject(model)
            case .summary(let s):
                EnrollmentSummaryView(summary: s).privacyCover().environmentObject(model)
            }
        }
    }
}

/// Asks for the app PIN when the model needs it (AppModel.withApproveKey). On the root and on sheets that sign.
struct PINPromptModifier: ViewModifier {
    @EnvironmentObject var model: AppModel
    @State private var pin = ""

    func body(content: Content) -> some View {
        content.alert("App PIN", isPresented: Binding(get: { model.pinPrompt != nil }, set: { _ in }),
                      presenting: model.pinPrompt) { p in
            SecureField("App PIN", text: $pin)
            Button("Continue") { answer(p, pin) }
            Button("Cancel", role: .cancel) { answer(p, nil) }
        } message: { p in
            Text(p.message ?? "Face ID did not open the approve key. Enter the app PIN set when this device was connected (not the phone's passcode).")
        }
    }

    private func answer(_ p: AppModel.PINPrompt, _ value: String?) {
        pin = ""
        if model.pinPrompt === p { model.pinPrompt = nil }
        p.finish(value)
    }
}

/// Covers the screen while the scene is not active, so the app switcher's snapshot (and anyone glancing at it) does not
/// show an open request, fingerprints or the device list. Not while the approve key's own Face ID prompt makes the
/// scene inactive: the person is looking at what they approve. On the root and on each sheet (a sheet sits above the
/// root's cover).
struct PrivacyCover: ViewModifier {
    @EnvironmentObject var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    private var covered: Bool {
        switch scenePhase {
        case .active: return false
        case .inactive: return model.signing == 0
        default: return true
        }
    }

    func body(content: Content) -> some View {
        content.overlay {
            if covered {
                ZStack {
                    Color(uiColor: .systemBackground)
                    Label("Interpose", systemImage: "lock.fill").font(.title2.weight(.semibold)).foregroundStyle(.secondary)
                }
                .ignoresSafeArea()
                .accessibilityElement(children: .combine)
                .accessibilityIdentifier("privacy-cover")
            }
        }
    }
}

extension View {
    func pinPrompt() -> some View { modifier(PINPromptModifier()) }
    func privacyCover() -> some View { modifier(PrivacyCover()) }
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
