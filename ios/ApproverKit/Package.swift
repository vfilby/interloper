// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "ApproverKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "ApproverKit", targets: ["ApproverKit"])],
    targets: [
        .target(name: "ApproverKit"),
        .testTarget(name: "ApproverKitTests", dependencies: ["ApproverKit"]),
    ]
)
