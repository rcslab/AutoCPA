#!/bin/sh

set -eu

if [ $# -ne 2 ]; then
    echo "Usage: $0 <KERNEL> <OUTPUT>" >&2
    exit 1
fi

mkdir -p "$2"

for FILE in "$1"/*; do
    if [ -x "$FILE" ]; then
        DEBUG="/usr/lib/debug/$FILE.debug"
        OUT="$2/$(basename "$FILE")"

        if [ -e "$DEBUG" ]; then
            ./scripts/merge-debug.sh "$FILE" "$DEBUG" "$OUT"
        else
            cp "$FILE" "$OUT"
        fi
    fi
done
