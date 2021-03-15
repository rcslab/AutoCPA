#!/bin/sh

if [ $# -lt 1 ]; then
    cat >&2 <<EOF
Usage: $0 /path/to/binary [OPTS]
EOF
    exit 1
fi

ROOT=$(cd "$(dirname "$0")"/.. && pwd)
FULL=$1
SHORT=$(basename "$FULL")
GHIDRA_HEADLESS=${GHIDRA_HEADLESS:-/usr/local/share/ghidra/support/analyzeHeadless}

mkdir -p "$ROOT/ghidra-projects"

$GHIDRA_HEADLESS "$ROOT/ghidra-projects" "$SHORT" -import "$FULL" -processor x86:LE:64:default -cspec gcc -postScript DWARF_ExtractorScript.java

shift
$GHIDRA_HEADLESS "$ROOT/ghidra-projects" "$SHORT" -process "$SHORT" -processor x86:LE:64:default -cspec gcc -noanalysis -scriptPath "$ROOT/scripts" -postScript StructOrderAnalysis.java "$ROOT/data/address_info.csv" "$@"
