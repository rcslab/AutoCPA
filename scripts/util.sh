#!/bin/sh

set -eu

GHIDRA="$ROOT/ghidra"
GHIDRA_VERSION=ghidra_11.1.2_PUBLIC
GHIDRA_CONFIG="${XDK_CONFIG_HOME:-$HOME/.config}/ghidra/$GHIDRA_VERSION"
GHIDRA_DATE=20240709
GHIDRA_ROOT=${GHIDRA_ROOT:-"$GHIDRA/$GHIDRA_VERSION"}
GHIDRA_PROJECTS=${GHIDRA_PROJECTS:-"$GHIDRA/projects"}

ghidra_headless() {
    # Clear the cache of .class files in case they're out of sync
    OSGI_DIR="$GHIDRA_CONFIG/osgi/compiled-bundles"
    if [ -d "$OSGI_DIR" ]; then
        rm -r "$OSGI_DIR"
    fi

    # The analyzeHeadless script doesn't allow JVM parameters to changed from
    # what it sets, so launch it manually with our parameters instead

    # Run in the foreground
    LAUNCH_MODE=fg
    # Default max memory threshold
    MAXMEM=
    # No custom JVM args
    VMARG_LIST=

    mkdir -p "$GHIDRA_PROJECTS"

    "$GHIDRA_ROOT/support/launch.sh" "$LAUNCH_MODE" jdk Ghidra-Headless "$MAXMEM" "$VMARG_LIST" ghidra.app.util.headless.AnalyzeHeadless "$GHIDRA_PROJECTS" "$@"
}
