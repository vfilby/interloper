// Renders the app icon: swift ios/tools/make-icon.swift ios/Approver/Assets.xcassets/AppIcon.appiconset/AppIcon-1024.png
import AppKit

// 1024x1024 opaque app icon: indigo gradient, white shield-with-checkmark symbol.
let size = 1024
let cs = CGColorSpace(name: CGColorSpace.sRGB)!
let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                    bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)! // no alpha: App Store requirement
let top = CGColor(srgbRed: 0.24, green: 0.20, blue: 0.62, alpha: 1)
let bottom = CGColor(srgbRed: 0.08, green: 0.07, blue: 0.24, alpha: 1)
let grad = CGGradient(colorsSpace: cs, colors: [top, bottom] as CFArray, locations: [0, 1])!
ctx.drawLinearGradient(grad, start: CGPoint(x: 0, y: CGFloat(size)), end: CGPoint(x: 0, y: 0), options: [])

let cfg = NSImage.SymbolConfiguration(pointSize: 560, weight: .semibold)
    .applying(.init(paletteColors: [NSColor(srgbRed: 0.16, green: 0.13, blue: 0.43, alpha: 1), .white]))
guard let sym = NSImage(systemSymbolName: "checkmark.shield.fill", accessibilityDescription: nil)?.withSymbolConfiguration(cfg) else {
    fatalError("symbol missing")
}
var rect = CGRect(origin: .zero, size: sym.size)
guard let cg = sym.cgImage(forProposedRect: &rect, context: nil, hints: nil) else { fatalError("no cgimage") }
let w = CGFloat(cg.width), h = CGFloat(cg.height)
let scale = min(600 / w, 600 / h)
let dw = w * scale, dh = h * scale
ctx.draw(cg, in: CGRect(x: (CGFloat(size) - dw) / 2, y: (CGFloat(size) - dh) / 2 - 10, width: dw, height: dh))

let out = CommandLine.arguments[1]
let rep = NSBitmapImageRep(cgImage: ctx.makeImage()!)
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: out))
print("wrote \(out)")
