#!/bin/sh

ROOT=$(realpath "$(dirname "$0")/..")
. "$ROOT/scripts/util.sh"

mkdir -p "$GHIDRA"
cd "$GHIDRA"

echo "Downloading Ghidra"
GHIDRA_ZIP=${GHIDRA_VERSION}_${GHIDRA_DATE}.zip
GHIDRA_BUILD=${GHIDRA_VERSION%_PUBLIC}_build
GHIDRA_BUILD=G${GHIDRA_BUILD#g}
curl -LOC- "https://github.com/NationalSecurityAgency/ghidra/releases/download/$GHIDRA_BUILD/$GHIDRA_ZIP"

echo "Extracting Ghidra"
unzip -qo "$GHIDRA_ZIP"
cd "$GHIDRA_ROOT"

echo "Patching Ghidra"
patch -p1 <"$ROOT/scripts/ghidra.patch"

echo "Building Ghidra (C++)"
OS=$(uname | tr '[A-Z]' '[a-z]')
ARCH=$(uname -m | tr '[A-Z]' '[a-z]')
if [ "$ARCH" = amd64 ]; then
    ARCH=x86_64
fi

CC=clang
CXX=clang++
if [ "$OS" = freebsd ]; then
    CC="$CC -I/usr/local/include"
    CXX="$CXX -I/usr/local/include"
fi

if command -v gmake >/dev/null; then
    MAKE=gmake
else
    MAKE=make
fi

if command -v nproc >/dev/null; then
    MAKE="$MAKE -j$(nproc)"
fi

$MAKE -C Ghidra/Features/Decompiler/src/decompile/cpp ghidra_opt CC="$CC" CXX="$CXX"
$MAKE -C Ghidra/Features/Decompiler/src/decompile/cpp sleigh_opt CC="$CC" CXX="$CXX"

OUT=Ghidra/Features/Decompiler/os/"${OS}_${ARCH}"
mkdir -p "$OUT"
cp Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_opt "$OUT"/decompile
cp Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_opt "$OUT"/sleigh
