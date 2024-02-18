// swift-tools-version:5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "ShadowSwift",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "ShadowSwift",
            targets: ["ShadowSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.2.3"),
        .package(url: "https://github.com/apple/swift-crypto", from: "3.2.0"),
        .package(url: "https://github.com/apple/swift-log", from: "1.5.3"),

        .package(url: "https://github.com/OperatorFoundation/Chord", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/Datable", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/KeychainTypes", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/Net", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/Straw", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/Transmission", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/TransmissionAsync", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/TransmissionTransport", branch: "main"),
        .package(url: "https://github.com/OperatorFoundation/Transport", branch: "main"),
    ],
    targets: [
        .target(
            name: "ShadowSwift",
            dependencies: [
                "Net",
                "Chord",
                "Datable",
                "KeychainTypes",
                "Straw",
                "Transmission",
                "TransmissionAsync",
                "TransmissionTransport",
                "Transport",

                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log")
            ]),
        .testTarget(
            name: "ShadowSwiftTests",
            dependencies: [
                        "Datable",
                        "KeychainTypes",
                        "ShadowSwift",
                        "Chord",
                        .product(name: "Logging", package: "swift-log")],
            exclude: ["Info.plist", "testsip008.json"]),
    ],
    swiftLanguageVersions: [.v5]
)
