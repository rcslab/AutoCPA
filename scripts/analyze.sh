#!/bin/sh

if [ $# -lt 2 ]; then
    cat >&2 <<EOF
Usage: $0 /path/to/projects /path/to/address_info.csv /path/to/binary [OPTS]
EOF
    exit 1
fi

ROOT=$(realpath $(dirname "$0")/..)
PROJ=$(realpath "$1")
FULL=$(realpath "$3")
CSV=$(realpath "$2")
SHORT=$(basename "$FULL")
GHIDRA_HEADLESS=${GHIDRA_HEADLESS:-/usr/local/share/ghidra/support/analyzeHeadless}

mkdir -p "$PROJ"

if [ ! -e "$PROJ/$SHORT.gpr" ]; then
    $GHIDRA_HEADLESS "$PROJ" "$SHORT" -import "$FULL" -processor x86:LE:64:default -max-cpu 24 -cspec gcc -postScript DWARF_ExtractorScript.java
fi

shift 3
$GHIDRA_HEADLESS "$PROJ" "$SHORT" -process -recursive -processor x86:LE:64:default -max-cpu 24 -cspec gcc -noanalysis -scriptPath "$ROOT/scripts" -postScript StructOrderAnalysis.java "$CSV" "$@"
