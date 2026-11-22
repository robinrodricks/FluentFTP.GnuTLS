#!/bin/bash

TUSER=/home/????

TBLD=x86_64-pc-linux-gnu

# Target x86_64/W64
THOST=x86_64-w64-mingw32
TPFX=$TUSER/mkgnutls/builds/gnutls/x86_64-w64
TCC=x86_64-w64-mingw32-gcc

# Target ARM64/Win64
# sudo apt install binutils-aarch64-w64-mingw32 gcc-aarch64-w64-mingw32
#THOST=aarch64-w64-mingw32
#TPFX=$TUSER/mkgnutls/builds/gnutls/aarch64-w64
#TCC=aarch64-w64-mingw32-gcc

######################

export THOST=$THOST
export TBLD=$TBLD
export TPFX=$TPFX
export PATH="$TPFX/bin:$PATH"
export CPPFLAGS="-I$TPFX/include"
export LDFLAGS="-L$TPFX/lib"
export LD_LIBRARY_PATH="-L$TPFX/lib"
export PKG_CONFIG_PATH="$TPFX/lib/pkgconfig"

echo "Current Environment:"
echo "===================="
echo -e "\r\n"
echo "HOST: $THOST"
echo "BLD:  $TBLD"
echo "PFX:  $TPFX"
echo "FLAGS:"
echo "CPPFLAGS=$CPPFLAGS"
echo "LDFLAGS=$LDFLAGS"
echo "LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo "PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
echo -e "\r\n"

cd sources

rm -rf gnutls-3.8.0
rm gnutls-3.8.0.tar.xz

wget https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.0.tar.xz
tar xvf gnutls-3.8.0.tar.xz

cd gnutls-3.8.0

autoreconf -f -i

CC_FOR_BUILD=gcc CC=$TCC ./configure \
--build=$TBLD \
--host=$THOST \
--prefix="$TPFX" \
--enable-shared \
--disable-static \
--without-p11-kit \
--with-included-libtasn1 \
--with-included-unistring \
--enable-local-libopts \
--disable-srp-authentication \
--disable-dtls-srtp-support \
--disable-heartbeat-support \
--disable-psk-authentication \
--disable-anon-authentication \
--disable-openssl-compatibility \
--without-tpm \
--disable-cxx \
--disable-guile \
--disable-doc \
--disable-maintainer-mode \
--disable-libdane \
ARFLAGS="cr"

make && make install

cd ~/mkgnutls
