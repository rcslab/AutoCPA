#!/bin/sh

set -eu

if [ $# -lt 3 ]; then
    echo "Usage: $0 <KERNEL> <KLDSTAT.OUT> <KERNEL.CSV> [ARGS...]" >&2
    exit 1
fi

KERNEL=$1
KLDSTAT=$2
CSV=$3
shift 3

: >"$CSV"

while read id refs base size name; do
    if [ "$base" = "Address" ]; then
        continue
    fi

    ./bcpiquery/bcpiquery extract -o "$KERNEL/$name" "$@"
    if [ "$name" = "kernel" ]; then
        cat address_info.csv >>"$CSV"
    else
        while IFS=',' read addr rest; do
            printf '%x,%s\n' "$(($base + 0x$addr))" "$rest"
        done <address_info.csv >>"$CSV"
    fi
done <"$KLDSTAT"
