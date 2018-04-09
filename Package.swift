// swift-tools-version:4.0

import PackageDescription

let package = Package(
    name: "SecureSockets",
    products: [
        .library(name: "SecureSockets", targets: ["SecureSockets"])
    ],
    dependencies: [
        .package(url: "https://github.com/Balancingrock/SwifterSockets", from: "0.11.0"),
        .package(url: "https://github.com/Balancingrock/COpenSsl", from: "0.3.0")
    ],
    targets: [
        .target(
            name: "SecureSockets",
            dependencies: ["SwifterSockets"]
        )
    ]
)
