#!/bin/sh

ROOT=$(realpath "$(dirname "$0")/..")
. "$ROOT/scripts/util.sh"

mkdir -p "$GHIDRA"
cd "$GHIDRA"

GHIDRA_ZIP=${GHIDRA_VERSION}_${GHIDRA_DATE}.zip
GHIDRA_BUILD=${GHIDRA_VERSION%_PUBLIC}_build
GHIDRA_BUILD=G${GHIDRA_BUILD#g}
curl -LOC- "https://github.com/NationalSecurityAgency/ghidra/releases/download/$GHIDRA_BUILD/$GHIDRA_ZIP"

unzip -u "$GHIDRA_ZIP"

# Ghidra doesn't support FreeBSD, so its OperatingSystem is null
# FreeBSD can run the Linux binaries however, so just symlink them
ln -sf linux_x86_64 "$GHIDRA_ROOT/GPL/DemanglerGnu/os/null"
ln -sf linux_x86_64 "$GHIDRA_ROOT/Ghidra/Features/Decompiler/os/null"
