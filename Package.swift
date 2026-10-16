// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ISAT",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "ISAT", targets: ["ISAT"]),
        .library(name: "ScannerKit", targets: ["ScannerKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/jpsim/Yams.git", from: "5.1.0"),
    ],
    targets: [
        .executableTarget(
            name: "ISAT",
            dependencies: ["ScannerKit"],
            path: "Sources/ISAT",
            resources: [
                .copy("Resources/ipatool"),
            ]
        ),
        .target(
            name: "ScannerKit",
            dependencies: [
                .product(name: "Yams", package: "Yams"),
            ],
            path: "Sources/ScannerKit",
            resources: [
                .copy("Resources/Rules"),
                .copy("Resources/dashboard"),
                .copy("Resources/report"),
            ]
        ),
        .testTarget(
            name: "ScannerKitTests",
            dependencies: ["ScannerKit"],
            path: "Tests/ScannerKitTests"
        ),
    ]
)
