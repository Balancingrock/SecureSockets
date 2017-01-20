import PackageDescription

let package = Package(
    name: "SecureSockets",
    dependencies: [
        .Package(url: "https://github.com/Swiftrien/SwifterSockets", "0.9.8")
    ]
)
