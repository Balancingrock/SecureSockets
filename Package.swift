// swift-tools-version:5.0

import PackageDescription

let package = Package(
    name: "SecureSockets",
    platforms: [
        .macOS(.v10_12)
    ],
    products: [
        .library(name: "SecureSockets", targets: ["SecureSockets"]),
        .library(name: "Copenssl", targets: ["Copenssl"]),
        .library(name: "CopensslGlue", targets: ["CopensslGlue"])
    ],
    dependencies: [
        .package(url: "https://github.com/Balancingrock/SwifterSockets", from: "1.1.1")
    ],
    targets: [
        .systemLibrary(name: "Copenssl"),
        .target(name: "CopensslGlue"),
        .target(
            name: "SecureSockets",
            dependencies: ["SwifterSockets", "Copenssl", "CopensslGlue"],
            //
            // Uncomment the following line for stand-alone or Xcode generation when included in another project
            swiftSettings: [.unsafeFlags(["-Iopenssl/v1_1_1g-macos_10_15/include"])],
            linkerSettings: [
                .linkedLibrary("ssl"),
                .linkedLibrary("crypto"),
                //
                // Uncomment the following line for stand-alone or Xcode generation when included in another project
                .unsafeFlags(["-Lopenssl/v1_1_1g-macos_10_15/lib"])
            ]
        )
    ]
)
