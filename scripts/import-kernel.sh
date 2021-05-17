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

cat_or_kldstat "$3" | tail -n+2 | while read id refs address size name; do
    $GHIDRA_HEADLESS "$PROJ" "$SHORT" -import "$FULL/$name" -processor x86:LE:64:default -cspec gcc -loader ElfLoader -loader-imagebase "$address" -max-cpu 24 -preScript DWARF_ExtractorScript.java
done
