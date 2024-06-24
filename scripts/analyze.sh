#!/bin/sh

ROOT=$(realpath "$(dirname "$0")/..")
. "$ROOT/scripts/util.sh"

usage() {
    echo "Usage: $0 [-a ANALYSIS] /path/to/binary [ARGS]"
}

ANALYSIS=StructOrderAnalysis

while getopts 'a:h' opt; do
    case "$opt" in
        a)
            ANALYSIS="$OPTARG"
            ;;
        h)
            usage
            exit
            ;;
        *)
            usage >&2
            exit 1
            ;;
    esac
done

shift $((OPTIND - 1))
if [ $# -lt 1 ]; then
    usage >&2
    exit 1
fi

FULL=$(realpath -- "$1")
SHORT=$(basename -- "$FULL")
shift

if [ "$FULL" != "${FULL%.csv}" ]; then
    {
        echo "Error: parameter order has changed for this script."
        echo "The CSV file should now come after the binary, e.g."
        echo
        echo "    $0 /bin/echo echo.csv"
        echo
        usage
    } >&2
    exit 1
fi

if [ ! -e "$GHIDRA_PROJECTS/$SHORT.gpr" ]; then
    ghidra_headless "$SHORT" -import "$FULL" -processor x86:LE:64:default -max-cpu 24 -cspec gcc
fi

ghidra_headless "$SHORT" -processor x86:LE:64:default -max-cpu 24 -cspec gcc -noanalysis -scriptPath "$ROOT/scripts" -postScript "$ANALYSIS.java" "$@"
