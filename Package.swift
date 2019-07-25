// swift-tools-version:5.0

import PackageDescription

let package = Package(
    name: "SecureSockets",
    products: [
        .library(name: "SecureSockets", targets: ["SecureSockets"])
    ],
    dependencies: [
        .package(url: "https://github.com/Balancingrock/SwifterSockets", from: "0.12.0")
    ],
    targets: [
        .systemLibrary(
            name: "COpenSsl"
        ),
        .target(
            name: "SecureSockets",
            dependencies: ["SwifterSockets", "COpenSsl"]
        )
    ]
)
