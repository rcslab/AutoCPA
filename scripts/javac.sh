#!/bin/sh

ROOT=$(realpath "$(dirname "$0")/..")
. "$ROOT/scripts/util.sh"

set -eu

JARS=$(find "$GHIDRA_ROOT" -name '*.jar' | tr '\n' ':')
find "$ROOT/scripts" -name '*.java' -exec javac -Xdiags:verbose -Xlint:deprecation -Xlint:unchecked -proc:none -classpath "$ROOT/scripts:$JARS" {} +
find "$ROOT/scripts" -name '*.class' -delete
