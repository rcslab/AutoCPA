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
mkdir -p Ghidra/Framework/Utility/src/main/java
unzip -qo -d Ghidra/Framework/Utility/src/main/java Ghidra/Framework/Utility/lib/Utility-src.zip
mkdir -p Ghidra/Framework/Generic/src/main/java
unzip -qo -d Ghidra/Framework/Generic/src/main/java Ghidra/Framework/Generic/lib/Generic-src.zip

echo "Patching Ghidra"
patch -p1 <"$ROOT/scripts/ghidra.patch"

echo "Building Ghidra (Java)"
JARS=$(find Ghidra -name '*.jar' | tr '\n' ':')
javac -classpath "$JARS" Ghidra/Framework/Utility/src/main/java/ghidra/framework/OperatingSystem.java
jar uf Ghidra/Framework/Utility/lib/Utility.jar -C Ghidra/Framework/Utility/src/main/java ghidra/framework/OperatingSystem.class
javac -classpath "$JARS" Ghidra/Framework/Generic/src/main/java/ghidra/framework/Platform.java
jar uf Ghidra/Framework/Generic/lib/Generic.jar -C Ghidra/Framework/Generic/src/main/java ghidra/framework/Platform.class

echo "Building Ghidra (C++)"
OS=$(uname | tr '[A-Z]' '[a-z]')
ARCH=$(uname -m | tr '[A-Z]' '[a-z]')

CC=clang
CXX=clang++
if [ "$OS" = freebsd ]; then
    CC="$CC -I/usr/local/include"
    CXX="$CXX -I/usr/local/include"
fi

gmake -C Ghidra/Features/Decompiler/src/decompile/cpp -j$(sysctl -n hw.ncpu) ghidra_opt CC="$CC" CXX="$CXX"
gmake -C Ghidra/Features/Decompiler/src/decompile/cpp -j$(sysctl -n hw.ncpu) sleigh_opt CC="$CC" CXX="$CXX"

OUT=Ghidra/Features/Decompiler/os/"${OS}_${ARCH}"
mkdir -p "$OUT"
cp Ghidra/Features/Decompiler/src/decompile/cpp/ghidra_opt "$OUT"/decompile
cp Ghidra/Features/Decompiler/src/decompile/cpp/sleigh_opt "$OUT"/sleigh
