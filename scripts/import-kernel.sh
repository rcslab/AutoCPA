#!/bin/sh

if [ $# -lt 1 ]; then
    echo "Usage: $0 /path/to/kernel [/path/to/kldstat.out]" >&2
    exit 1
fi

ROOT=$(realpath "$(dirname "$0")/..")
. "$ROOT/scripts/util.sh"

FULL="$1"
SHORT=$(basename "$FULL")

cat_or_kldstat() {
    if [ -n "$1" ]; then
        cat "$1"
    else
        kldstat
    fi
}

cat_or_kldstat "${2-}" | tail -n+2 | while read id refs address size name; do
    if ! ghidra_headless "$SHORT" -import "$FULL/$name" -loader ElfLoader -loader-imagebase "$address" -max-cpu 24; then
        printf '%s: Error importing %s\n' "$0" "$FULL/$name" >&2
        printf '%s: Project may be incomplete; continuing...\n' "$0" >&2
    fi
done
