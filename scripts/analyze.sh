#!/bin/sh

if [ $# -ne 1 ]; then
    cat >&2 <<EOF
Usage: $0 /path/to/binary
EOF
    exit 1
fi

ROOT=$(cd "$(dirname "$0")"/.. && pwd)
FULL=$1
SHORT=$(basename "$FULL")
GHIDRA_HEADLESS=${GHIDRA_HEADLESS:-/usr/local/share/ghidra/support/analyzeHeadless}

mkdir -p "$ROOT/ghidra-projects"

$GHIDRA_HEADLESS "$ROOT/ghidra-projects" "$SHORT" -import "$FULL" -postScript DWARF_ExtractorScript.java
$GHIDRA_HEADLESS "$ROOT/ghidra-projects" "$SHORT" -process "$SHORT" -noanalysis -scriptPath "$ROOT/scripts" -postScript StructOrderAnalysis.java "$ROOT/data/address_info.csv" "$ROOT/data/lst_map.csv"
