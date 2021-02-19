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
HEADLESS=/usr/local/share/ghidra/support/analyzeHeadless

mkdir -p "$ROOT/ghidra-projects"

$HEADLESS "$ROOT/ghidra-projects" "$SHORT" -import "$FULL" -postScript DWARF_ExtractorScript.java
$HEADLESS "$ROOT/ghidra-projects" "$SHORT" -process "$SHORT" -noanalysis -scriptPath "$ROOT/scripts" -postScript create-table.py "$ROOT/data/$SHORT.pkl"
$HEADLESS "$ROOT/ghidra-projects" "$SHORT" -process "$SHORT" -noanalysis -scriptPath "$ROOT/scripts" -postScript analysis-cachemiss.py "$ROOT/data/address_info.csv" "$ROOT/data/$SHORT.pkl"
