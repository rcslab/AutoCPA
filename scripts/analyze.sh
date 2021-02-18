#!/bin/sh

if [ $# -ne 1 ]; then
    cat >&2 <<EOF
Usage: $0 /path/to/binary
EOF
    exit 1
fi

ROOT=$(cd "$(dirname "$0")"/.. && pwd)
BINARY=$1
BIN=$2

mkdir -p "$ROOT/ghidra-projects"

headless() {
    /usr/local/share/ghidra/support/analyzeHeadless "$ROOT/ghidra-projects" bcpi -import "$BINARY" -readOnly -scriptPath "$ROOT" -postScript "$@"
}

headless scripts/create-table.py "$ROOT/data/pickle.pkl"
headless scripts/analysis-cachemiss.py "$ROOT/data/address_info.csv" "$ROOT/data/pickle.pkl"
