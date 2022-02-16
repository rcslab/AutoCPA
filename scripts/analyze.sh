#!/bin/sh

ROOT=$(realpath "$(dirname "$0")/..")
. "$ROOT/scripts/util.sh"

if [ $# -lt 2 ]; then
    echo "Usage: $0 /path/to/address_info.csv /path/to/binary [OPTS]" >&2
    exit 1
fi

CSV=$(realpath "$1")
FULL=$(realpath "$2")
SHORT=$(basename "$FULL")

if [ ! -e "$GHIDRA_PROJECTS/$SHORT.gpr" ]; then
    ghidra_headless "$SHORT" -import "$FULL" -processor x86:LE:64:default -max-cpu 24 -cspec gcc -scriptPath "$ROOT/scripts" -preScript BcpiDwarf.java
fi

shift 2
ghidra_headless "$SHORT" -processor x86:LE:64:default -max-cpu 24 -cspec gcc -noanalysis -scriptPath "$ROOT/scripts" -postScript StructOrderAnalysis.java "$CSV" "$@"
