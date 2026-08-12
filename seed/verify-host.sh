#!/usr/bin/env bash
# Check the bootstrapped runtime is usable: right Java, Ghidra present, extension installed.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck disable=SC1091
source "$script_dir/env.sh"

fail=0
note() { echo "  $1"; }

if [[ -x "$JAVA_HOME/bin/java" ]]; then
    note "java: $("$JAVA_HOME/bin/java" -version 2>&1 | head -1)"
else
    echo "missing: $JAVA_HOME/bin/java" >&2; fail=1
fi

for required in \
    "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" \
    "$GHIDRA_INSTALL_DIR/Ghidra/Framework" \
    "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/LibGhidraHost/extension.properties"
do
    if [[ -e "$required" ]]; then
        note "ok: ${required#"$GHIDRASQL_KIT_ROOT/"}"
    else
        echo "missing: $required" >&2; fail=1
    fi
done

# The headless server lives in the extension's ghidra_scripts; without it the host
# starts and then fails to find anything to run, which reads as a confusing timeout.
script="$GHIDRA_INSTALL_DIR/Ghidra/Extensions/LibGhidraHost/ghidra_scripts/LibGhidraHeadlessServer.java"
if [[ -f "$script" ]]; then
    note "ok: LibGhidraHeadlessServer.java"
else
    echo "missing: $script" >&2; fail=1
fi

(( fail == 0 )) || { echo "Runtime verification FAILED." >&2; exit 1; }
echo "Runtime verified: Ghidra $GHIDRA_VERSION + JDK $JDK_VERSION + LibGhidraHost."
