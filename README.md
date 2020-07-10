# SecureSockets

A collection of secure socket layer utilities written in Swift using openSSL.

SecureSockets is part of the Swiftfire webserver project.

The [Swiftfire webpage](http://swiftfire.nl)

The [reference manual](http://swiftfire.nl/projects/securesockets/reference/index.html)

<sub>(_Never mind the github report that it is mostly C, that report is misleading because of openssl include files_)</sub>

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
- Builds for macOS, iOS, tvOS and Linux (Ubuntu, we used the Mint 19.3 distribution) (Reduced API for iOS and tvOS)

__Note on iOS and tvOS usage__: While SecureSockets does build for these platforms, we ourselves have not used it on these platforms. Also we have no guidelines on how to integrate it into an iOS/tvOS project. In addition it will be necessary to cross-compile openSSL for these platforms, a task that is made easier by the script at [OpenSSL-for-iPhone](https://github.com/x2on/OpenSSL-for-iPhone).

If you have used SecureSockets on iOS or tvOS, and are willing to share the process on how to do so, please let us know at: rien@balancingrock.nl.

# Installation

The manifest file `Package.swift` has been prepared with a dependency build in mind. Hence it must be edited to build to a stand-alone SecureSockets target.

## As a stand alone

When SecureSockets is build as stand-alone product the installation is as follows:

    $ git clone https://github.com/balancingrock/SecureSockets.git
    $ cd SecureSockets
    <<edit Package.swift>>
    $ swift build

The step `<<edit Package.swift>>` is to un-comment either the openssl linux libraries or the openssl macOS libaries.

## As a dependency on the command line

SecureSockets can be used by the Swift Package Manager. Just add it to your package manifest as a dependency.

To build the project that uses SecureSockets add the following options to the build command:

    $ swift build -Xswiftc -I/<<path>>/openssl/<<version-platform>>/include -Xlinker -L/<<path>>/openssl/<<version-platform>>/lib

where `<<path>>` must be set to the proper value and `<<version-make>>` to the openssl version and the platform necessary.

Alternatively it may be possible to include these in the product manifest.

## As a dependency using Xcode for development

The Swiftfire project is used as an example.

1. Clone the project repository and create a Xcode project:

        $ git clone https://github.com/Balancingrock/Swiftfire.git
        $ cd Swiftfire
        $ swift package generate-xcodeproj

1. Double click the project to open it.

1. In the navigator select `Swiftfire`, then under `Targets` select `CopensslGlue` then select `Build Settings`
    - In `Linking` add the value `-lssl -lcrypto` to `Other Linker Flags`.
    - In `Search Paths` add the value `$(SRCROOT)/openssl/v1_1_1g-macos_10_15/lib` to `Library Search Paths`
    - in `Search Paths` add the value `$(SRCROOT)/openssl/v1_1_1g-macos_10_15/include` to `Header Search Paths` (be sure to leave a blank character between the content that was already present and the additional content)

1. In the navigator select `Swiftfire`, then under `Targets` select `SecureSockets` then select `Build Settings`
- in `Search Paths` add the value `$(SRCROOT)/openssl/v1_1_1g-macos_10_15/include` to `Header Search Paths` (be sure to leave a blank character between the content that was already present and the additional content)

The build process should now be able to complete.

# Version history

No new features planned. Updates are made on an ad-hoc basis as needed to support Swiftfire development.

#### 1.1.2 - 1.1.8

- Rapid prototyping for iOS and tvOS compatibility
- Removed assignNewRsa from non- macOS/Linux targets
- Added swift version, platform and a LICESE file.

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
