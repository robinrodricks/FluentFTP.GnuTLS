#!/bin/bash

TUSER=/home/????

TBLD=x86_64-pc-linux-gnu

# Target x86_64/W64
THOST=x86_64-w64-mingw32
TPFX=$TUSER/mkgnutls/builds/gnutls/x86_64-w64
TCC=x86_64-w64-mingw32-gcc

# For other targets
#THOST=?
#TPFX=$TUSER/mkgnutls/builds/gnutls/?
#TCC=?

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

rm -rf gmp-6.2.1
rm gmp-6.2.1.tar.lz

wget https://ftp.gnu.org/gnu/gmp/gmp-6.2.1.tar.lz
tar xvf gmp-6.2.1.tar.lz

cd gmp-6.2.1

CC_FOR_BUILD=gcc ./configure --host=$THOST --prefix="$TPFX" --disable-static --enable-shared --enable-fat CFLAGS="-Wno-attributes"

make && make install

cd ~/mkgnutls

exit

