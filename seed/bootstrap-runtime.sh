#!/usr/bin/env bash
# One-time runtime setup: fetch the pinned Ghidra and JDK, verify their digests, install
# the prebuilt LibGhidraHost extension. Compiles nothing.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck disable=SC1091
source "$script_dir/env.sh"

downloads="$GHIDRASQL_KIT_ROOT/var/downloads"
runtime="$GHIDRASQL_KIT_ROOT/runtime"
mkdir -p "$downloads" "$runtime"

# unzip is deliberately NOT required — env.sh's seed_unzip falls back to python3.
for command_name in curl tar sha256sum; do
    command -v "$command_name" >/dev/null || {
        echo "Required bootstrap command is missing: $command_name" >&2
        exit 1
    }
done
if ! command -v unzip >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
    echo "Need either unzip or python3 to unpack archives; install one and re-run." >&2
    exit 1
fi

fetch() {  # url sha256 dest
    local url="$1" sha="$2" dest="$3"
    # --continue-at resumes a partial download: the transport on these VMs is often
    # proxied and can cut a large transfer short.
    if [[ ! -f "$dest" ]] || ! echo "$sha  $dest" | sha256sum -c --status; then
        echo "fetching $(basename "$dest") ..."
        # -sS: no progress meter (it renders as thousands of lines in a CI log) but
        # still report real errors.
        curl -L --fail --retry 5 --continue-at - -sS -o "$dest" "$url"
    fi
    echo "$sha  $dest" | sha256sum -c
}

fetch "$GHIDRA_URL" "$GHIDRA_SHA256" "$downloads/$GHIDRA_ARCHIVE"
fetch "$JDK_URL" "$JDK_SHA256" "$downloads/$JDK_ARCHIVE"

seed_unzip "$downloads/$GHIDRA_ARCHIVE" "$runtime"
tar -xzf "$downloads/$JDK_ARCHIVE" -C "$runtime"

# Ghidra's launcher reads its settings through bash process substitution (`done < <(...)`),
# which needs /dev/fd. Some sandboxes do not provide it, and the launcher then fails
# before Ghidra starts. Probe rather than guess, and only patch when the probe fails so
# a normal machine keeps upstream's file untouched.
launch_script="$runtime/$GHIDRA_DIRNAME/support/launch.sh"
if ! ( : < <(echo probe) ) 2>/dev/null; then
    if grep -q 'done < <(' "$launch_script" 2>/dev/null; then
        echo "process substitution unavailable -> patching Ghidra's launcher"
        patch --batch --forward -p0 -d "$runtime" \
            < "$GHIDRASQL_KIT_ROOT/patches/ghidra-launch-no-dev-fd.patch"
    fi
fi

mkdir -p "$runtime/$GHIDRA_DIRNAME/Ghidra/Extensions"
seed_unzip "$GHIDRASQL_KIT_ROOT/extensions/LibGhidraHost-ghidra-$GHIDRA_VERSION.zip" \
    "$runtime/$GHIDRA_DIRNAME/Ghidra/Extensions"

"$script_dir/verify-host.sh"
echo "Pinned Ghidra $GHIDRA_VERSION and JDK $JDK_VERSION installed. Nothing was compiled."
