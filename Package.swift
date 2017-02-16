import PackageDescription

let package = Package(
    name: "SecureSockets",
    dependencies: [
        .Package(url: "../SwifterSockets", "0.9.14"),
        .Package(url: "https://github.com/Balancingrock/COpenSsl", "0.1.0")
    ]
)
