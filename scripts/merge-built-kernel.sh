#!/bin/sh

set -eu

if [ $# -ne 2 ]; then
    echo "Usage: $0 <KERNEL> <OUTPUT>" >&2
    exit 1
fi

mkdir -p "$2"

find "$1" -name '*.full' -exec sh -c 'cp "$1" "$2/$(basename "$1" .full)"' sh {} "$2" \;
