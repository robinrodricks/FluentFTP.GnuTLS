# FluentFTP.GnuTLS
Premiere .NET wrapper for GnuTLS along with integration into FluentFTP

## Package
Published as [FluentFTP.GnuTLS](https://www.nuget.org/packages/FluentFTP.GnuTLS).

## Docs
See [FluentFTP Wiki](https://github.com/robinrodricks/FluentFTP/wiki/FTPS-Connection-using-GnuTLS).

## Developer Setup

According to the GnuTLS LGPL license, you need to be able to obtain the
source code of the original GnuTLS library or the source code of any derivate
or modification of the GnuTLS library.

The `FluentFTP.GnuTLS` wrapper uses the ORIGINAL unmodified GnuTLS library as a `.dll`
that is dynamically linked.

As of this writing, the GnuTLS library version needed is 3.7.8.

This guide is for building GnuTLS-30.dll and its dependencies from their respective
original official source.

### 1. Setup and use a fresh install of WSL2 using Debian Bullseye (Debian 11)

Read up on how to export, import, de-register and download WSL2 images for use on your
Windows PC.

Do NOT use an existing Debian 11 image. Export it in order to save it and install a fresh one.

Perform the following steps in WSL2(Debian 11), work as root or use sudo appropriately:

### 2. Preparation

Perform this once:

    > mkdir mkgnutls && cd mkgnutls

    > apt-get install wget git subversion gettext lzip automake autoconf autogen autopoint \
    libtool make colormake pkg-config wx-common mingw-w64 mingw-w64-tools

    > mkdir sources && mkdir builds && mkdir builds/gnutls && mkdir builds/gnutls/client64


### 3. Building

In order to download the sources, build and install these libraries, use the scripts in the `Libs/Build` folder.

- libgmp:     ``run step1.sh``
- libnettle:  ``run step2.sh``
- libgnutls:  ``run step3.sh``


### 4. Optionally strip symbols from `.dll`

- ``run step4.sh``

### 5. Finalize

You will find the built files in the folder `mkgnutls/builds/gnutls/client64/bin`:

- `libgmp-10.dll`
- `libnettle-8.dll`
- `libhogweed-6.dll`
- `libgnutls-30.dll` 
- `libgcc_s_seh-1.dll` (part of the `mingw-w64` toolchain)
- `libwinpthread-1.dll` (part of the `mingw-w64` toolchain)

### 6. Build FluentFTP.GnuTLS

Use Visual Studio to build `FluentFTP.GnuTLS`, which will include the Windows DLLs and Linux binaries in the package.