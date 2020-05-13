// swift-tools-version:5.0

import PackageDescription

let package = Package(
    name: "SecureSockets",
    platforms: [
        .macOS(.v10_12)
    ],
    products: [
        .library(name: "SecureSockets", targets: ["SecureSockets"]),
        .library(name: "COpenSsl", targets: ["COpenSsl"])
    ],
    dependencies: [
        .package(url: "../SwifterSockets", from: "1.1.0")
    ],
    targets: [
        .systemLibrary(
            name: "COpenSsl"
        ),
        .target(
            name: "SecureSockets",
            dependencies: ["SwifterSockets", "COpenSsl"],
            //
            // Uncomment the following line for stand-alone or Xcode generation
            swiftSettings: [.unsafeFlags(["-Iopenssl/v1_1_0-macos_10_12/include"])],
            linkerSettings: [
                .linkedLibrary("ssl"),
                .linkedLibrary("crypto"),
                //
                // Uncomment the following line for stand-alone or Xcode generation
                .unsafeFlags(["-Lopenssl/v1_1_0-macos_10_12/lib"])
            ]
        )
    ]
)
