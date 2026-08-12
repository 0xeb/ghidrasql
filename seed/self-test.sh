#!/usr/bin/env bash
# End-to-end proof that this seed actually works: bootstrap -> analyze -> query -> stop.
#
# CI runs this before publishing, so a seed that cannot answer a query is never released.
# It is also the fastest way for an agent to confirm its environment is sane.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck disable=SC1091
source "$script_dir/env.sh"

target="${1:-/bin/ls}"
port="${2:-${GHIDRASQL_PORT:-8099}}"
project_dir="$GHIDRASQL_KIT_ROOT/var/projects/selftest"

[[ -r "$target" ]] || { echo "self-test target not readable: $target" >&2; exit 2; }

cleanup() { "$script_dir/shutdown.sh" "$port" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[1/5] verify seed"
"$script_dir/verify-seed.sh" >/dev/null

echo "[2/5] bootstrap runtime (no-op if already installed)"
"$script_dir/bootstrap-runtime.sh" >/dev/null

echo "[3/5] analyze $target"
rm -rf "$project_dir"
"$script_dir/run-headless.sh" "$target" "$project_dir" selftest "$port" >/dev/null

echo "[4/5] query"
count_json="$("$script_dir/query.sh" 'SELECT COUNT(*) AS n FROM funcs;' "$port")"
count="$(printf '%s' "$count_json" | sed -n 's/.*"rows":\[\["\([0-9]*\)"\]\].*/\1/p')"
if [[ -z "$count" || "$count" -le 0 ]]; then
    echo "self-test FAILED: expected a positive function count, got: $count_json" >&2
    exit 1
fi
echo "      funcs: $count"

# A count alone can come from a stub; ask for real rows too.
names_json="$("$script_dir/query.sh" \
    "SELECT name, printf('0x%X', addr) AS addr FROM funcs ORDER BY size DESC LIMIT 3;" "$port")"
printf '%s' "$names_json" | grep -q '"rows":\[\[' || {
    echo "self-test FAILED: no function rows returned: $names_json" >&2
    exit 1
}

echo "[5/5] shutdown"
"$script_dir/shutdown.sh" "$port" >/dev/null
trap - EXIT

echo "SELF-TEST PASSED: $target analyzed, $count functions, clean shutdown."
