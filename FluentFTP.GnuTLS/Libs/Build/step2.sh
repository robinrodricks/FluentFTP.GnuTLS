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

rm -rf nettle-3.9.1
rm nettle-3.9.1.tar.gz

wget https://ftp.gnu.org/gnu/nettle/nettle-3.9.1.tar.gz
tar xvf nettle-3.9.1.tar.gz

cd nettle-3.9.1

./configure --host=$THOST --prefix="$TPFX" --enable-shared --disable-static --enable-fat 

make && make install

cd ~/mkgnutls
