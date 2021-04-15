#!/bin/sh

if [ $# -lt 2 ]; then
    echo "Usage: $0 /path/to/projects /path/to/kernel [/path/to/kldstat.out]" >&2
    exit 1
fi

ROOT=$(realpath $(dirname "$0")/..)
PROJ=$(realpath "$1")
FULL=$(realpath "$2")
SHORT=$(basename "$FULL")
GHIDRA_HEADLESS=${GHIDRA_HEADLESS:-/usr/local/share/ghidra/support/analyzeHeadless}

mkdir -p "$PROJ"

cat_or_kldstat() {
    if [ -n "$1" ]; then
        cat "$1"
    else
        kldstat
    fi
}

cat_or_kldstat "$3" | while read id refs address size name; do
    if [ "$address" = "Address" ]; then
        continue
    fi

    $GHIDRA_HEADLESS "$PROJ" "$SHORT" -import "$FULL/$name" -loader ElfLoader -loader-imagebase "$address" -processor x86:LE:64:default -max-cpu 24 -cspec gcc -postScript DWARF_ExtractorScript.java
done
