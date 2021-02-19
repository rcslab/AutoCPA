#!/bin/sh

# https://stackoverflow.com/a/17599967/502399

TMP="$(mktemp -d "${TMPDIR:-/tmp}"/merge-debug.XXXXXXXXXX)"

objcopy $(objdump -h "$2" \
        | awk '$2~/^\.debug/' \
        | while read idx name size vma lma off align; do
        echo " --add-section=$name=$TMP/$name.raw"
        {
            # https://stackoverflow.com/a/1280828/502399
            dd bs=1 skip=0x$off count=0 status=none
            dd bs=4096 count=$((0x$size / 4096)) status=none
            dd bs=$((0x$size % 4096)) count=1 status=none
        } <"$2" >"$TMP/$name.raw"
    done) "$1" "$3"

rm -rf "$TMP"
