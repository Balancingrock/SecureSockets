# SecureSockets
A collection of secure socket layer utilities in Swift using openSSL.

Depends on SwifterSockets and COpenSsl.

SecureSockets is part of [Swiftfire](http://swiftfire.nl), the next generation personal webserver.

# OpenSSL

OpenSSL is available from [https://openssl.org](https://openssl.org).

Due to limitations in the interface between Swift and C there are two functions that must be added to the openSSL libraries. Due to limitations in the Swift Package Manager, these functions cannot be added as a seperate library. The easiest solution is to put these functions in the openSSL code.

Instructions are included below.

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

# Documentation

Project page: [SecureSockets](http://swiftfire.nl/projects/securesockets/securesockets.html)

Reference: [reference manual](http://swiftfire.nl/projects/securesockets/reference/index.html)

# Installation

SecureSockets is distributed as a SPM package. But it depends on the openSSL libraries.

To provide a positive user experience, the SecureSockets repository contains a version of openSSL 1.1.0 compiled for MacOS 10.12. This allows the user of the package to simply clone & build the library.

However this is not recommened. You should not trust the distributed version of openSSL but build your own from the original sources.

The instructions to build openSSL are included below. For now just go ahead, but be sure to later replace the openSSL library with a build of your own.

Unfortunately an existing build of openSSL (for example from `brew` or `macports`) cannot be used. Some variadic functions need glue code so that Swift is able to call the (variadic) functions. This glue has to be added to the openSSL code as per instructions further below.

## Use as SPM dependency

This is the default situation. Just add it to the dependencies of your project.

To build your project two arguments must be set:

    $ swift build -Xswiftc -I/__your_path__/openssl/v1_1_0-macos_10_12/include -Xlinker -L/__your_path__/openssl/v1_1_0-macos_10_12/lib

where `__your_path__` must be set to the proper value.

## Build as a standalone project

To create a local copy use the git clone command:

    $ git clone https://github.com/Swiftrien/SecureSockets
    $ cd SecureSockets
    
Now edit the file `Package.swift` and uncomment the two lines that specify the compiler & linker options.
Then:
    
    $ swift build

## Generate an Xcode project

As for _Build as a standalone project_ but there is no need to _build_ the project, instead use:

    $ swift package generate-xcodeproj
    
The compiler an dlinker settings will be filled in by the above command.

## Use inside an XCode project as a SPM dependency

Include SecureSockets as a dependency in the Package.swift manifest file.

Under the target settings add the following _Build Settings_:

_<project-name> -> <target> -> Build Settings -> Search Paths -> (Add to) Header Search Paths: $(SRCROOT)/openssl/v1_1_0-macos_10_12/include_
_<project-name> -> <target> -> Build Settings -> Search Paths -> (Add to) Library Search Paths: $(SRCROOT)/openssl/v1_1_0-macos_10_12/lib_

# Version history

Note: Planned releases are for information only, they are subject to change without notice.

#### 1.1.0 (Open)

- No new features planned. Features and bugfixes will be made on an ad-hoc basis as needed to support Swiftfire development.
- For feature requests and bugfixes please contact rien@balancingrock.nl

#### 1.0.0 (Current)

- Reorganized for release 1.0.0

# Installing OpenSSL

## Download & verification

SecureSockets was developped for openSSL 1.1.0. but should be compatible with 1.1.1 (Note that these versions are not compatible with the previous version 1.0.2)

The download link for openSSL is: [https://www.openssl.org/source](https://www.openssl.org/source/)

Right-click the openssl-1.1.0c.tar.gz file and select "save-as" to download it to your downloads folder.

Use the save-as option because we want the openssl-1.1.0c.tar.gz file. Also download the sha256 checksum. After the download finishes, open up a terminal window and cd to the download folder. Calculate the sha256 checksum of the gz file with:

    $ shasum -a 256 openssl-1.1.0c.tar.gz

The next line should display the checksum. Compare that with the downloaded checksum, they should of course be equal. (Open a text editor and put the two checksums below each other, that way it is easy to verify)

Now unpack the gz and tar file to obtain the openssl-1.1.0c folder. A singe double click should do the trick.

## Adding C2Swift glue code

Note: being pragmatic about this, I used the files as shown below. Somebody with more openSSL knowledge could probably identify much better places for this. You yourself might find better places. In the end, it does not really matter, all that is necessary is for the Swift code to find the two pieces of glue code. Where it is placed is largely uncritical (as long as the C language visibility rules are respected).

### ssl.h

Find the file `openssl-1.1.0c/include/openssl/ssl.h`

At the very end, but before the last line insert:

    void sslCtxSetTlsExtServernameCallback(SSL_CTX *ctx, int (*cb)(const SSL *ssl, int *num, void *arg), void *arg);

After inserting this the last bit of the file should look as follows:

    # define SSL_R_X509_LIB                                   268
    # define SSL_R_X509_VERIFICATION_SETUP_PROBLEMS           269

    # ifdef  __cplusplus
    }
    # endif

    void sslCtxSetTlsExtServernameCallback(SSL_CTX *ctx, int (*cb)(const SSL *ssl, int *num, void *arg), void *arg);

    #endif
 
### ssl_lib.c

Find the file `openssl-1.1.0c/ssl/ssl_lib.c`
At the very end, after the #endif, include the following:

    void sslCtxSetTlsExtServernameCallback(SSL_CTX *ctx, int (*cb)(const SSL *ssl, int *num, void *arg), void *arg) {
        SSL_CTX_set_tlsext_servername_arg(ctx, arg);
        SSL_CTX_set_tlsext_servername_callback(ctx, cb);
    }

After inserting this the last bit of the file should look as follows:

    const CTLOG_STORE *SSL_CTX_get0_ctlog_store(const SSL_CTX *ctx)
    {
        return ctx->ctlog_store;
    }

    #endif

    void sslCtxSetTlsExtServernameCallback(SSL_CTX *ctx, int (*cb)(const SSL *ssl, int *num, void *arg), void *arg) {
        SSL_CTX_set_tlsext_servername_arg(ctx, arg);
        SSL_CTX_set_tlsext_servername_callback(ctx, cb);
    }

### x509v3.h

Find the file `openssl-1.1.0c/include/openssl/x509v3.h`
At the very end, before the #endif, include the following:

    void skGeneralNamePopFree(STACK_OF(GENERAL_NAME) *san_names);

After inserting this the last bit of the file should look as follows:

    # define X509V3_R_UNSUPPORTED_TYPE                        167
    # define X509V3_R_USER_TOO_LONG                           132

    # ifdef  __cplusplus
    }
    # endif

    void skGeneralNamePopFree(STACK_OF(GENERAL_NAME) *san_names);
    #endif

### v3_addr.c

Find the file `openssl-1.1.0c/crypto/x509v3/v3_addr.c`
At the very end, after the #endif, include the following:

    void skGeneralNamePopFree(STACK_OF(GENERAL_NAME) *san_names) {
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    }

After inserting this the last bit of the file should look as follows:

        return addr_validate_path_internal(NULL, chain, ext);
    }

    #endif                          /* OPENSSL_NO_RFC3779 */

    void skGeneralNamePopFree(STACK_OF(GENERAL_NAME) *san_names) {
        sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    }


## Building the libraries

Next we should build the libraries and include files.

The OpenSSL 1.1.0 installer needs PERL 5.10 or later.

    $ perl -v

The [installation instructions](https://wiki.openssl.org/index.php/Compilation_and_Installation) on the openSSL site are a little confusing, but the process is very simple. In the INSTALL file in the openssl-1.1.0c directory we find the proper installation instructions for Unix.

BEWARE:  By default openssl will be installed in `/usr/local`. This will clash with possible `brew` installations. Hence it is recommended to specify a different location during `config`. (Note use the `--prefix` and `--openssldir` options.)

Note: It is not possible to use `brew` because of the small additions as discussed before.

First run config:

Note: Do this while the terminal prompt is in the openssl-1.1.0 directory!

    $ ./config --prefix=/__your-path__ --openssldir=/__your-path__

Messages start scrolling but it is over rather quick.
There should not be any visible issues.

Next is:

    $ make

This takes a little longer. When it stops (and again no visible problems):

    $ make test

A lot of tests are executed, some may be skipped. The result should show:

    All tests successful.
    Files=89, Tests=477, 44 wallclock secs ( 0.37 usr  0.16 sys + 30.58 cusr  7.34 csys = 38.45 CPU)
    Result: PASS

The next step:

    $ sudo make install

Again a lot of messages scrolls over the screen. (Note that this step takes by far the most time)

Since this is for API use only there is no need to adjust PATH variables or anything.
