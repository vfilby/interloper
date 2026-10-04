import ApproverKit
import SwiftUI

/// Authoritative first: title, requester, on-behalf-of, facts (all written by the adapter from the service's own
/// state). The requester's reason comes after, quoted and labelled as their claim.
struct RequestDetailView: View {
    @EnvironmentObject var model: AppModel
    let req: OpenedRequest
    @State private var working = false
    @State private var pin = ""
    @State private var usePIN = false

    private var r: Record { req.record }

    var body: some View {
        List {
            Section {
                Text(sanitize(r.title)).font(.title3.weight(.semibold))
                LabeledContent("Requester", value: sanitize(r.requester))
                if let who = r.onBehalfOf {
                    LabeledContent("On behalf of") {
                        VStack(alignment: .trailing) {
                            Text(sanitize(who.display ?? who.principal))
                            Text("attested by \(sanitize(who.attestedBy))").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                ForEach(r.facts ?? [], id: \.self) { f in
                    LabeledContent(sanitize(f.label)) {
                        Text(sanitize(f.value)).foregroundStyle(f.color).fontWeight(f.level?.isEmpty == false ? .semibold : .regular)
                    }
                }
                if let l = r.lease {
                    LabeledContent("Lease", value: "\(sanitize(l.scope)) for \(Duration.seconds(l.durationS).formatted(.units(allowed: [.hours, .minutes])))"
                                   + ((l.maxUses ?? 0) > 0 ? ", max \(l.maxUses!) uses" : ""))
                }
                LabeledContent("Expires") { Text(Date(timeIntervalSince1970: TimeInterval(r.expiresAt)), style: .relative) }
            } header: {
                Text("\(sanitize(r.adapter)) · \(sanitize(r.kind))")
            } footer: {
                if r.isHighRisk { Text("High risk: approving needs a long press, then Face ID.").foregroundStyle(.red) }
            }

            if let reason = r.reason, !reason.isEmpty {
                Section("Reason given by \(sanitize(r.requester)) (their claim)") {
                    Text("“\(sanitize(reason))”").italic()
                }
            }

            Section {
                let outcome = model.outcomes[req.id]
                if let outcome {
                    // A note (rejected / failed) or an unconfirmed ack leaves the request actionable: a new tap signs a
                    // fresh decision on the same record.
                    OutcomeText(outcome: outcome)
                }
                if r.isExpired() {
                    Text("Expired").foregroundStyle(.secondary)
                } else if outcome?.allowsDecision ?? true {
                    if !model.isInsecure {
                        Toggle("Use app PIN instead of Face ID", isOn: $usePIN)
                        if usePIN { SecureField("App PIN", text: $pin).keyboardType(.numberPad) }
                    }
                    if r.isHighRisk {
                        HoldToConfirmButton(title: "Hold to approve") { decide(true) }
                    } else {
                        Button { decide(true) } label: {
                            Label("Approve", systemImage: "faceid").frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                    }
                    Button(role: .destructive) { decide(false) } label: {
                        Text("Deny").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }
            }
            .disabled(working)
        }
        .navigationTitle("Request")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func decide(_ approve: Bool) {
        working = true
        Task {
            await model.decide(req, approve: approve, pin: usePIN ? pin : nil)
            working = false
        }
    }
}

/// The second deliberate gesture for high-risk approvals: press and hold until the bar fills.
struct HoldToConfirmButton: View {
    let title: String
    let action: () -> Void
    var duration: Double = 1.5
    @State private var pressing = false

    var body: some View {
        Text(title)
            .font(.headline)
            .foregroundStyle(.white)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background {
                GeometryReader { g in
                    ZStack(alignment: .leading) {
                        Color.red.opacity(0.45)
                        Color.red.frame(width: pressing ? g.size.width : 0)
                            .animation(pressing ? .linear(duration: duration) : .easeOut(duration: 0.2), value: pressing)
                    }
                }
            }
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .onLongPressGesture(minimumDuration: duration, perform: action, onPressingChanged: { pressing = $0 })
            .accessibilityAddTraits(.isButton)
            .accessibilityHint("Press and hold to approve")
    }
}
