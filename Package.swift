import PackageDescription

let package = Package(
    name: "SecureSockets",
    dependencies: [
        .Package(url: "https://github.com/Balancingrock/SwifterSockets", "0.10.2"),
        .Package(url: "https://github.com/Balancingrock/COpenSsl", "0.1.0")
    ]
)
