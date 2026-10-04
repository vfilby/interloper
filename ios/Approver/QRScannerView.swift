import ApproverKit
import SwiftUI
import VisionKit

/// Scans the enrollment QR code from the server's management page. Only a code that parses as an enrollment link is
/// taken; anything else stays on screen and the scanner keeps looking.
struct QRScannerSheet: View {
    var onLink: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    static var isAvailable: Bool { DataScannerViewController.isSupported && DataScannerViewController.isAvailable }

    var body: some View {
        NavigationStack {
            QRScanner { payload in
                guard EnrollmentLink(payload) != nil else { return false }
                onLink(payload)
                dismiss()
                return true
            }
            .ignoresSafeArea()
            .navigationTitle("Scan QR code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            }
        }
    }
}

private struct QRScanner: UIViewControllerRepresentable {
    /// Returns true once a payload is accepted, which stops scanning.
    var onPayload: (String) -> Bool

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {}

    static func dismantleUIViewController(_ scanner: DataScannerViewController, coordinator: Coordinator) {
        scanner.stopScanning()
    }

    func makeCoordinator() -> Coordinator { Coordinator(onPayload: onPayload) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onPayload: (String) -> Bool
        private var done = false

        init(onPayload: @escaping (String) -> Bool) { self.onPayload = onPayload }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem],
                         allItems: [RecognizedItem]) {
            guard !done else { return }
            for case .barcode(let code) in items {
                if let s = code.payloadStringValue, onPayload(s) {
                    done = true
                    scanner.stopScanning()
                    return
                }
            }
        }
    }
}
