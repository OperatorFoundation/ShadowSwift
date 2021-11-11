// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ShadowSwift",
    platforms: [
        .macOS(.v11),
        .iOS(.v14)],
    products: [
        .library(
            name: "ShadowSwift",
            targets: ["ShadowSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/OperatorFoundation/Chord.git", from: "0.0.15"),
        .package(url: "https://github.com/OperatorFoundation/Datable.git", from: "3.1.2"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.4.2"),
        .package(url: "https://github.com/OperatorFoundation/SwiftHexTools.git", from: "1.2.2"),
        .package(url: "https://github.com/OperatorFoundation/Transmission.git", from: "1.0.4"),
        .package(url: "https://github.com/OperatorFoundation/Transport.git", from: "2.3.5"),
        .package(url: "https://github.com/apple/swift-crypto", from: "2.0.0")
    ],
    targets: [
        .target(
            name: "ShadowSwift",
            dependencies: [
                "Chord",
                "Datable",
                "Transmission",
                "Transport",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Crypto", package: "swift-crypto")
            ]),
        .testTarget(
            name: "ShadowSwiftTests",
            dependencies: [
                        "Datable",
                        "ShadowSwift",
                        "SwiftHexTools",
                        "Chord",
                        .product(name: "Logging", package: "swift-log")],
            exclude: ["Info.plist"]),
    ],
    
    swiftLanguageVersions: [.v5]
)
