#!/bin/sh

if [ $# -ne 2 ]; then
    echo "Usage: $0 /path/to/projects /path/to/kernel" >&2
    exit 1
fi

ROOT=$(realpath $(dirname "$0")/..)
PROJ=$(realpath "$1")
FULL=$(realpath "$2")
SHORT=$(basename "$FULL")
GHIDRA_HEADLESS=${GHIDRA_HEADLESS:-/usr/local/share/ghidra/support/analyzeHeadless}

mkdir -p "$PROJ"

kldstat | tail -n+2 | while read id refs address size name; do
    $GHIDRA_HEADLESS "$PROJ" "$SHORT" -import "$FULL/$name" -loader ElfLoader -loader-imagebase "$address" -processor x86:LE:64:default -max-cpu 24 -cspec gcc -postScript DWARF_ExtractorScript.java
done
