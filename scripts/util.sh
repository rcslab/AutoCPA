#!/bin/sh

set -eu

GHIDRA="$ROOT/ghidra"
GHIDRA_VERSION=ghidra_10.1.2_PUBLIC
GHIDRA_DATE=20220125
GHIDRA_ROOT=${GHIDRA_ROOT:-"$GHIDRA/$GHIDRA_VERSION"}
GHIDRA_PROJECTS=${GHIDRA_PROJECTS:-"$GHIDRA/projects"}

ghidra_headless() {
    # The analyzeHeadless script doesn't allow JVM parameters to changed from
    # what it sets, so launch it manually with our parameters instead

    # Run in the foreground
    LAUNCH_MODE=fg
    # Default max memory threshold
    MAXMEM=
    # No custom JVM args
    VMARG_LIST=

    mkdir -p "$GHIDRA_PROJECTS"

    # Ghidra's launch.sh uses eval, so quote the parameters with Bash's printf %q
    "$GHIDRA_ROOT/support/launch.sh" "$LAUNCH_MODE" Ghidra-Headless "$MAXMEM" "$VMARG_LIST" ghidra.app.util.headless.AnalyzeHeadless "$GHIDRA_PROJECTS" $(bash -c 'printf "%q " "$@"' bash "$@")
}
