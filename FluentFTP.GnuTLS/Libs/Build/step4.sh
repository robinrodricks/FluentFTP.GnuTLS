#!/bin/bash

TUSER=/home/????

TBLD=x86_64-pc-linux-gnu

# Target x86_64/W64
# sudo apt install binutils-x86_64-w64-mingw32 gcc-x86_64-w64-mingw32
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

$THOST-strip $TPFX/bin/*.dll

cd ~/mkgnutls
