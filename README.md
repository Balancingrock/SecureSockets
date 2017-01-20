#PRERELEASE!! Do not use

# SecureSockets
A collection of secure socket layer utilities in Swift using openSSL.

Depends on SwifterSockets.

SecureSockets is part of the 5 packages that make up the [Swiftfire](http://swiftfire.nl) webserver:

#####[SwifterSockets](https://github.com/Swiftrien/SwifterSockets)

Basic POSIX sockets utilities.

#####[Swiftfire](https://github.com/Swiftrien/Swiftfire)

An open source web server in Swift.

#####[SwifterLog](https://github.com/Swiftrien/SwifterLog)

General purpose logging utility.

#####[SwifterJSON](https://github.com/Swiftrien/SwifterJSON)

General purpose JSON framework.

#OpenSSL

OpenSSL is available from [https://openssl.org](https://openssl.org)

OpenSSL (v1.1.0b) headers and binary (compiled for macOS 10.11) are included in this distribution to prevent build errors during initial install.

However, please do not trust this binary and build your own from the openSSL.org website. Instructions are included below. Note that v1.1.0b is no longer the most recent version. This should add to the incentive to download & build openSSL yourself!

The openSSL license is included at the end of this document.

#Features
- Shields the Swift application from the complexity of the Unix socket and openSSL calls.
- Directly interfaces with the openSSL calls using:
	- connectToSslServer
	- sslTransfer
	- sslReceiverLoop
	- sslAccept
	- setupSslServer
- Implements a framework on top of the POSIX calls with:
	- connectToSslServer (returns a SwifterSockets.Connection)
	- SslServer (class, produces SwifterSockets.Connection's)
- Builds as a library using the Swift Package Manager (SPM) & Xcode
- Supports
	- certified server operations
	- certified server & certified clients
	- multiple domain certificates (SNI) on a certified server

#Installation

While SecureSockets is distributed as an SPM package, it currently cannot be build using SPM. This is due to the fact that SecureSockets uses (just a few lines) of C code. SPM currently only supports pure Swift code packages. Hopefully this will be fixed or added in the future.

It is therefore __necessary to use both SPM and Xcode__.

(Ironically Xcode also cannot build the SecureSockets library either since Xcode does not allow bridge headers in library targets)

It thus takes a bit of work to create the library. Of course it is also possible to use the source as such. If that route is choosen, be sure to update (or add) the bridging header, the C module, the openSSL headers and the openSSL libraries.

To create the library use the following steps:

Note: it is necessary to work around some shortcomings of the SPM and Xcode, so some steps may look arcane...

These are the exact steps used on a MacBook Pro with macOS 10.12, Xcode 8.2.1 for SecureSockets 0.1.0.

1 - Create a SecureSockets directory:

    $ mkdir SecureSockets

2 - Go down the new directory and initialize a package:

    $ cd SecureSockets
    $ swift package init

3 - Create a Xcode project:

    $ swift package generate-xcodeproj

4 - Clone the SecureSockets project but keep the xcode project that was generated:

    $ cd ..
    $ mv SecureSockets/SecureSockets.xcodeproj .
    $ rm -rf SecureSockets
    $ git clone https://github.com/Swiftrien/SecureSockets
    $ mv SecureSockets.xcodeproj SecureSockets

5 - Download the dependancy SwifterSockets by attempting a build of the SecureSocket project with SPM:

    $ cd SecureSockets
    $ swift build
    
6 - Note that the above step invokes a compilation that will fail. But the download of SwifterSockets should be successful.

7 - Change directory to /Packages/SwifterSockets-0.9.8:

    $ cd Packages/SwifterSockets-0.9.8

8 - Create an xcode project:

    $ swift package generate-xcodeproj
    
9 - Start Xcode and open the SwifterSockets project.

10 - Build SwifterSockets in Xcode. When ready (no errors or warnings) select the SwifterSockets.framework in the Products folder and see where it is stored. This location is needed to import the framework into the SecureSockets project in step 13.

11 - Open the SecureSockets project in xcode (the SwifterSockets project can be closed).

12 - From the file menu, use the "Add Files" to add the files in the _Sources_ folder to the project (all of them. _SecureSockets.swift_ will be already present). 

13 - Select the target and add the _SwifterSockets.framework_ that was created in step 10.
    
14 - Add the openSSL libraries as well:

	openssl/lib/libssl.a
	openssl/lib/libcrypto.a
	
15 - Add a search path for the openSSL header in the build settings under _Search Paths_, _Header Search Paths_ (note: the path should be: _openssl/include_)

16 - Add the bridge header in the build settings under _Swift Compiler - General_, _Objective-C Bridging Header_ (note: the path should be: _Sources/SecureSockets-Bridge.h_)

17 - Since the openssl libraries have been compiled for macOS 10.11, the _Deployment Target_ should be set to 10.11.

18 - Build the project, there should be no errors or warnings. In the Xcode Products folder there should be a SecureSockets.framework.



#Version history

Note: Planned releases are for information only, they are subject to change without notice.

####v1.1.0 (Open)

- No new features planned. Features and bugfixes will be made on an ad-hoc basis as needed to support Swiftfire development.
- For feature requests and bugfixes please contact rien@balancingrock.nl

####v1.0.0 (Planned)

- The current verion will be upgraded to 1.0.0 status when the full set necessary for Swiftfire 1.0.0 has been completed.

####v0.1.0 (Upcoming)

- Initial release

# Installing OpenSSL

SecureSockets needs openSSL 1.1.0. (Note that this version is not compatible with the previous version 1.0.2)

The download link for openSSL is: [https://www.openssl.org/source](https://www.openssl.org/source/)

Right-click the openssl-1.1.0c.tar.gz file and select "save-as" to download it to your downloads folder.

Use the save-as option because we want the openssl-1.1.0c.tar.gz file. Also download the sha256 checksum. After the download finishes, open up a terminal window and cd to the download folder. Calculate the sha256 checksum of the gz file with:

    $ shasum -a 256 openssl-1.1.0c.tar.gz

The next line should display the checksum. Compare that with the downloaded checksum, they should of course be equal. (Open a text editor and put the two checksums below each other, that way it is easy to verify)

Now unpack the gz and tar file to obtain the openssl-1.1.0c folder. A singe double click should do the trick.

Next we should build the libraries and include files.

The OpenSSL 1.1.0 installer needs PERL 5.10 or later.

    $ perl -v

The []installation instructions](https://wiki.openssl.org/index.php/Compilation_and_Installation) on the openSSL site are a little confusing, but the process is very simple. In the INSTALL file in the openssl-1.1.0c directory we find the proper installation instructions for Unix.

By default openssl will be installed in /usr/local. Check that there is no 'ssl' directory in '/usr/local'. To change the default, see the INSTALL document.

First run config:

Note: Do this while the terminal prompt is in the openssl-1.1.0 directory!

    $ ./config

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

The header files can be found in _openssl-1.1.0c/include/openssl_ copy these to the _openssl/include/openssl_ path in the SecureSockets directory. The libcrypto.a and libssl.a are in _openssl-1.1.0c_ and should be copied over to the _openssl/lib_ path in the SecureSockets directory.

Do not throw away the old headers and lib just yet, wait until a build of SecureSockets is successful. If such a build fails with a future version of openSSL, please let me know at rien@balancingrock.nl

# OpenSSL License

~~~~~
LICENSE ISSUES
  ==============

  The OpenSSL toolkit stays under a dual license, i.e. both the conditions of
  the OpenSSL License and the original SSLeay license apply to the toolkit.
  See below for the actual license texts.

  OpenSSL License
  ---------------

/* ====================================================================
 * Copyright (c) 1998-2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

 Original SSLeay License
 -----------------------

/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
 ~~~~~