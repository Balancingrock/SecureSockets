# SecureSockets

A collection of secure socket layer utilities in Swift using openSSL.

SecureSockets is part of the Swiftfire webserver project.

The [Swiftfire webpage](http://swiftfire.nl)

The [reference manual](http://swiftfire.nl/projects/securesockets/reference/index.html)

<sub>_Never mind the github report that it is mostly C, that report is misleading because of openssl include files_</sub>

# OpenSSL

OpenSSL is available from [https://openssl.org](https://openssl.org).

For convenience pre-compiled openSSL distributions are included in this package. While this is convenient for evaluation and development purposes, you should not use them for the final production version of your application. You owe it to your clients/users to only use fully guaranteed openSSL libraries. Which you have to build yourself.

Instructions are included in [Installing OpenSSL](docs/Installing%20OpenSSL.md).

# Features

- Shields the Swift application from the complexity of the Unix socket and openSSL calls.
- Directly interfaces with the openSSL calls using:
	- connectToSslServer
	- sslTransfer
	- sslReceiverLoop
	- sslAccept
	- setupSslServer
- Implements a framework on top of the openSSL calls with:
	- connectToSslServer (returns a SwifterSockets.Connection)
	- SslServer (class, produces SwifterSockets.Connection's)
- Builds as a package using the Swift Package Manager (SPM)
- Builds as a modular framework using Xcode.
- Supports
	- certified server operations
	- certified server & certified clients
	- multiple domain certificates (SNI) on a certified server
- Builds for macOS and Linux (Ubuntu, we used the Mint distribution)

# Installation

## As a product on macOS

When SecureSockets is build as its own product the installation is extremely simple:

    $ git clone https://github.com/balancingrock/SecureSockets.git
    $ cd SecureSockets
    $ swift build

That is it.

## As a product on Linux

    $ git clone https://github.com/balancingrock/SecureSockets.git
    $ cd SecureSockets
    <<fix Package.swift>>
    $ swift build

The step `<<fix Package.swift>>` is to un-comment the openssl linux libraries and to comment-out the openssl macOS libaries.

## As a dependency on the command line

SecureSockets can be used by the Swift Package Manager. Just add it to your package manifest as a dependency.

However there are two unsafe settings in the `Package.swift` manifest file that must be commented out before the project can be build. The are clearly marked in the manifest file. Instead these options must be specified on the command line when the product is build:

    $ swift build -Xswiftc -I/<<path>>/openssl/<<version-platform>>/include -Xlinker -L/<<path>>/openssl/<<version-platform>>/lib

where `<<path>>` must be set to the proper value and `<<version-make>>` to the openssl version and the platform necessary.

And of course the `Package.swift` manifest file must be adjusted for the platform, i.e. macOS or Linux.

## As a product in Xcode

1. Clone the repository and create a Xcode project:

        $ git clone https://github.com/Balancingrock/SecureSockets
        $ cd SecureSockets
        $ swift package generate-xcodeproj

1. Double click the project to open it.

1. In the navigator select `SecureSockets`, then under `Targets` select `CopensslGlue` then select `Build Settings`
    - In `Linking` add the value `-lssl -lcrypto` to `Other Linker Flags`.
    - In `Search Paths` add the value `$(SRCROOT)/openssl/v1_1_1g-macos_10_15/lib` to `Library Search Paths`
    - in `Search Paths` add the value `$(SRCROOT)/openssl/v1_1_1g-macos_10_15/include` to `Header Search Paths` (be sure to leave a blank character between the content that was already present and the additional content)

The build should now run flawless.

# Version history

No new features planned. Updates are made on an ad-hoc basis as needed to support Swiftfire development.

#### 1.1.1

- Linux compatibility
- Renaming COpenSsl to Copenssl
- Added CopensslGlue to simplify the build process.

#### 1.1.0

- Switched from BRUtils.Result to Swift.Result
- Added SecureSocketsResult based on Swift.Result
- Rewrote a few pointer usages to silence Swift 5.2 warnings

#### 1.0.1

- Documentation Updates

#### 1.0.0

- Reorganized for release 1.0.0
