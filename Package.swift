// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "JOSESwift",
    platforms: [.iOS(.v13), .macOS(.v10_15), .watchOS(.v8), .tvOS(.v15), .visionOS(.v1)],
    products: [
        .library(name: "JOSESwift", targets: ["JOSESwift"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.4")
    ],
    targets: [
        .target(
            name: "JOSESwift",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
                .product(name: "CryptoSwift", package: "CryptoSwift", condition: .when(platforms: [.linux]))
            ],
            path: "JOSESwift",
            exclude: ["Support/Info.plist"]
        ),
        .testTarget(
            name: "JOSESwiftTests",
            dependencies: ["JOSESwift"],
            path: "Tests",
            sources: [
                "ASN1DEREncodingTests.swift",
                "ASN1DERParsingTests.swift",
                "CryptoTestCase.swift",
                "DataExtensionTests.swift",
                "HMACCryptoTestCase.swift",
                "HMACSignerTests.swift",
                "HMACTests.swift",
                "HMACVerifierTests.swift"
            ]
        )
    ],
    swiftLanguageVersions: [.v5]
)
