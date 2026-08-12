#!/usr/bin/env bash
# Shared environment for every seed script. Source it; do not execute it.
#
# Each export here exists because its absence broke a real session:
#   JAVA_HOME + LD_LIBRARY_PATH  - a VM with a broken system Java failed to load libjli.so
#   TMPDIR + -Djava.io.tmpdir    - a VM with no usable /tmp failed on Java temp files
# Keeping them means a fresh agent session does not have to rediscover either one.

kit_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck disable=SC1091
source "$kit_root/scripts/versions.env"

export GHIDRASQL_KIT_ROOT="$kit_root"
export GHIDRA_INSTALL_DIR="$kit_root/runtime/$GHIDRA_DIRNAME"
export JAVA_HOME="$kit_root/runtime/$JDK_DIRNAME"
export PATH="$kit_root/bin:$JAVA_HOME/bin:$PATH"
export LD_LIBRARY_PATH="$JAVA_HOME/lib:$JAVA_HOME/lib/server${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

mkdir -p "$kit_root/var/tmp" "$kit_root/var/projects" "$kit_root/var/log" "$kit_root/var/run"
export TMPDIR="${GHIDRASQL_TMPDIR:-$kit_root/var/tmp}"

java_tmp_option="-Djava.io.tmpdir=$TMPDIR"
if [[ " ${JAVA_TOOL_OPTIONS:-} " != *" $java_tmp_option "* ]]; then
    export JAVA_TOOL_OPTIONS="${JAVA_TOOL_OPTIONS:+$JAVA_TOOL_OPTIONS }$java_tmp_option"
fi

# Unpack a .zip without assuming `unzip` exists.
#
# The VM this seed was designed for happened to have unzip; a plain Ubuntu 24.04 (and
# WSL) does not ship it, and the original bootstrap hard-failed there. python3 is far
# more reliably present, so fall back to it rather than telling the user to apt-install
# something mid-session.
seed_unzip() {
    local archive="$1" dest="$2"
    mkdir -p "$dest"
    if command -v unzip >/dev/null 2>&1; then
        unzip -q -o "$archive" -d "$dest"
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$archive" "$dest" <<'PY'
import sys, zipfile, os, stat
archive, dest = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(archive) as z:
    for info in z.infolist():
        path = z.extract(info, dest)
        # zipfile drops the executable bit; Ghidra's launchers need it back.
        mode = info.external_attr >> 16
        if mode and not info.is_dir():
            os.chmod(path, mode)
PY
    else
        echo "Cannot unpack $archive: neither unzip nor python3 is available." >&2
        echo "Install one of them (e.g. 'apt-get install -y unzip') and re-run." >&2
        return 1
    fi
}
