# SecureSockets

A collection of secure socket layer utilities in Swift using openSSL.

SecureSockets is part of the Swiftfire webserver project.

The [Swiftfire webpage](http://swiftfire.nl)

The [reference manual](http://swiftfire.nl/projects/securesockets/reference/index.html)

# OpenSSL

OpenSSL is available from [https://openssl.org](https://openssl.org).

Due to limitations in the interface between Swift and C there is some glue code that must be added to the openSSL libraries. Due to limitations in the Swift Package Manager, these functions cannot be added as a separate library. The easiest solution is to put these functions in the openSSL code.

Note that this glue code means that it is not possible to use an existing build of openSSL, for example from `brew` or `macports`.

For convenience a pre-compiled openSSL distribution is included in this package. While this is convenient for evaluation and development purposes, you should not use it for the final production version of your application. You owe it to your clients/users to only use fully guaranteed openSSL libraries. Which you must build yourself.

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

# Installation

## SPM

VJson can be used by the Swift Package Manager. Just add it to your package manifest as a dependency. However it is necessary to add two arguments to the build command:

    $ swift build -Xswiftc -I/__your_path__/openssl/v1_1_0-macos_10_12/include -Xlinker -L/__your_path__/openssl/v1_1_0-macos_10_12/lib

where `__your_path__` must be set to the proper value.

## Xcode

1. Clone the repository and create a Xcode project:

        $ git clone https://github.com/Balancingrock/SecureSockets
        $ cd SecureSockets
        $ swift package generate-xcodeproj

1. Double click that project to open it. Once open set the `Defines Module` to 'yes' in the `Build Settings -> Packaging` before creating the framework. (Otherwise the import of the framework in another project won't work)

1. In the project that will use SecureSockets, add the SecureSockets.framework by opening the `General` settings of the target and add the SecureSockets.framework to the `Embedded Binaries`.

1. In the project that uses SecureSockets add the following to the framework target and the application target under the `Build Settings`:

	_\<target\> -> Build Settings -> Search Paths -> (Add to) Header Search Paths: $(SRCROOT)/openssl/v1_1_0-macos_10_12/include_
	
	_\<target\> -> Build Settings -> Search Paths -> (Add to) Library Search Paths: $(SRCROOT)/openssl/v1_1_0-macos_10_12/lib_

1. In the Swift source code where you want to use it, import SecureSockets at the top of the file.

# Version history

No new features planned. Updates are made on an ad-hoc basis as needed to support Swiftfire development.

#### 1.0.1

- Documentation Updates

#### 1.0.0

- Reorganized for release 1.0.0
