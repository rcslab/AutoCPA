#!/bin/sh

# https://stackoverflow.com/a/17599967/502399

set -eu

if [ $# -ne 3 ]; then
    echo "Usage: $0 <BINARY> <DEBUG> <OUTPUT>" >&2
    exit 1
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}"/merge-debug.XXXXXXXXXX)"
READELF="${READELF:-/usr/local/bin/readelf}"

objcopy --remove-section=.gnu_debuglink \
        $(objdump -h "$2" \
              | awk '$2~/^\.debug/' \
              | while read idx name size vma lma off align; do
                    $READELF --relocated-dump="$name" "$2" | awk '{ print $2 $3 $4 $5 }' | xxd -r -p >"$TMP/$name.raw"
                    echo " --add-section=$name=$TMP/$name.raw"
                done
        ) \
        "$1" \
        "$3"

rm -rf "$TMP"
