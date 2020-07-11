# Installing OpenSSL

## Download & verification

SecureSockets was developped for openSSL 1.1.0. and is compatible with 1.1.1 (Note that these versions are not compatible with the previous version 1.0.2)

The download link for openSSL is: [https://www.openssl.org/source](https://www.openssl.org/source/)

MacOS: Right-click the `<<version>>.tar.gz` file and select "save-as" to download it to your downloads directory. Use the save-as option because we need the `<<version>>.tar.gz` file.

Linux: Download the `<<version>>.tar.gz` file.

Also download the sha256 checksum. 

Then open a command line window (Linux) or use Terminal (macOS) and change to the downloads directory:

    $ cd ~/Downloads

Calculate the sha256 checksum of the gz file with:

    $ shasum -a 256 <<version>>.tar.gz

The next line should display the checksum.

Compare that with the downloaded checksum.

    $ more <<version>>.tar.gz.sha256

The next line displays the checksum as it should be.

Both checksums should of course be equal. (Open a text editor and put the two checksums below each other, that way it is easy to verify)

Now unpack the gz and tar file to obtain the installation folder.

    $ tar -xf <<version>>.tar.gz

## Building the library

Next we should build the libraries and include files.

The openSSL installer needs PERL 5.10 or later.

    $ perl -v

On a clean Linux (Mint) install it may be necessary to install Perl and the necessary Text modules. See NOTES.PERL.

We follow these [installation instructions](https://wiki.openssl.org/index.php/Compilation_and_Installation). On first glance this may seem confusing, but the process is actually very simple.

First switch to the directory with the extracted files:

    $ cd <<version>>

If you like take a look at the README file, alternatively go right ahead and configure the build scripts:

    $ ./config --prefix=<<path>> --openssldir=<<path>>

We use the path `/home/me/Documents/Projects/openssl/<<version>>` on Linux and `/Users/me/Documents/Projects/openssl/<<version>>` on macOS. Any location is fine as long as no conflicts are created. Keep in mind that the path cannot contain the infamous `~` character. Also for SecureSockets it is best to use the same value for the `--prefix` and `--openssldir` options. Lastly if you do not use a path that has write access from your user account, then you must use the `sudo` command in front of the last make step (see below).

BEWARE:  By default openssl will be installed in `/usr/local`. This is not only not needed, but may class with an existing installation too.

After the command line is typed a coupe of messages will appear but it is over rather quick.
There should not be any visible issues.
If it did report any issues, then most likely the preconditions for installation were not met (for example PERL is missing some modules). Check the INSTALL, README and NOTES files for more information.

When configure is complete:

    $ make

This takes a little longer. When it stops (and again no visible problems):

    $ make test

A lot of tests are executed, some may be skipped. The result should show something like:

    All tests successful.
    Files=89, Tests=477, 44 wallclock secs ( 0.37 usr  0.16 sys + 30.58 cusr  7.34 csys = 38.45 CPU)
    Result: PASS

The next step:

    $ make install

If your account does not have the necessary write access to the path settings using in `config` above, then use `sudo` in front.

Again a lot of messages scrolls over the screen. (Note that this step takes by far the most time)

Since this is for API use only there is no need to adjust PATH variables or anything.

That is all. However the installation process created much more than we actually need. We only need the directories: `<<version>>/include` and `version/lib`. And from the `version/lib` directory we only need the `ssl.a` and `crypto.a` files.
It is recommened to copy these files to the `SecureSockets/openssl/<<version>>` directory overwriting the files already in there.
