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

echo "[1/11] verify seed"
"$script_dir/verify-seed.sh" >/dev/null

echo "[2/11] bootstrap runtime (no-op if already installed)"
"$script_dir/bootstrap-runtime.sh" >/dev/null

echo "[3/11] analyze $target"
rm -rf "$project_dir"
"$script_dir/run-headless.sh" "$target" "$project_dir" selftest "$port" >/dev/null

echo "[4/11] query"
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

echo "[5/11] push down instruction address ranges"
instruction_range_json="$(timeout 5 "$script_dir/query.sh" \
    'SELECT addr,mnemonic FROM instructions WHERE addr BETWEEN 0 AND 0x7fffffffffffffff LIMIT 3;' \
    "$port")"
printf '%s' "$instruction_range_json" | grep -q '"rows":\[\[' || {
    echo "self-test FAILED: bounded instruction range returned no rows: $instruction_range_json" >&2
    exit 1
}

echo "[6/11] push down exact callers"
target_json="$("$script_dir/query.sh" \
    "SELECT printf('0x%X', addr) AS addr FROM funcs ORDER BY addr LIMIT 1;" "$port")"
target_addr="$(printf '%s' "$target_json" | \
    sed -n 's/.*"rows":\[\["\(0x[0-9A-Fa-f]*\)"\]\].*/\1/p')"
[[ -n "$target_addr" ]] || {
    echo "self-test FAILED: could not select exact caller target: $target_json" >&2
    exit 1
}
callers_json="$(timeout 5 "$script_dir/query.sh" \
    "SELECT COUNT(*) AS n FROM callers WHERE func_addr = $target_addr;" "$port")"
printf '%s' "$callers_json" | grep -q '"success":true' || {
    echo "self-test FAILED: exact callers lookup did not complete: $callers_json" >&2
    exit 1
}

echo "[7/11] push down exact callees"
callees_json="$(timeout 5 "$script_dir/query.sh" \
    "SELECT COUNT(*) AS n FROM callees WHERE func_addr = $target_addr;" "$port")"
printf '%s' "$callees_json" | grep -q '"success":true' || {
    echo "self-test FAILED: exact callees lookup did not complete: $callees_json" >&2
    exit 1
}

echo "[8/11] bound synthetic ctree call projections"
ctree_args_json="$(timeout 5 "$script_dir/query.sh" \
    "SELECT COUNT(*) AS n FROM ctree_call_args WHERE func_addr = $target_addr;" "$port")"
printf '%s' "$ctree_args_json" | grep -q '"success":true' || {
    echo "self-test FAILED: exact ctree_call_args lookup did not complete: $ctree_args_json" >&2
    exit 1
}

echo "[9/11] reject unbounded constant lookup"
constants_json="$(timeout 5 "$script_dir/query.sh" \
    'SELECT * FROM constants WHERE value = 40000 LIMIT 1;' "$port")"
printf '%s' "$constants_json" | grep -q \
    'unbounded constants.value lookup is disabled' || {
    echo "self-test FAILED: unbounded constants.value did not fail fast: $constants_json" >&2
    exit 1
}

echo "[10/11] cancel foreground CLI queries with SIGINT"
set +e
cancel_output="$(timeout --preserve-status --signal=INT 1 \
    ghidrasql --url http://127.0.0.1:9 -q \
    'WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<1000000000) SELECT sum(x) FROM n;' \
    2>&1)"
cancel_rc=$?
set -e
if [[ "$cancel_rc" -ne 1 ]] || ! grep -q 'Query cancelled' <<<"$cancel_output"; then
    echo "self-test FAILED: foreground Ctrl-C did not cancel cleanly (rc=$cancel_rc): $cancel_output" >&2
    exit 1
fi

echo "[11/11] shutdown"
"$script_dir/shutdown.sh" "$port" >/dev/null
trap - EXIT

echo "SELF-TEST PASSED: $target analyzed, $count functions, clean shutdown."
