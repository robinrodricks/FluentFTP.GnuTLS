#!/bin/bash

TUSER=/root

TPFX=$TUSER/mkgnutls/builds/gnutls/client64 

THOST=x86_64-w64-mingw32
TBLD=x86_64-pc-linux

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

rm -rf gnutls-3.7.8
rm gnutls-3.7.8.tar.xz

wget https://www.gnupg.org/ftp/gcrypt/gnutls/v3.7/gnutls-3.7.8.tar.xz
tar xvf gnutls-3.7.8.tar.xz

cd gnutls-3.7.8

autoreconf -f -i

./configure \
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
