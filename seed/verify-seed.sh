#!/usr/bin/env bash
# Check the unpacked seed is complete and intact before anything is run.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck disable=SC1091
source "$script_dir/env.sh"

cd "$GHIDRASQL_KIT_ROOT"

missing=0
for required in bin/ghidrasql SHA256SUMS PROVENANCE.md prompts/ghidrasql_agent.md; do
    [[ -e "$required" ]] || { echo "missing: $required" >&2; missing=1; }
done
compgen -G "extensions/LibGhidraHost-ghidra-*.zip" >/dev/null \
    || { echo "missing: extensions/LibGhidraHost-ghidra-*.zip" >&2; missing=1; }
(( missing == 0 )) || exit 1

# Content check, not just presence: a truncated download is the failure this catches.
sha256sum -c --quiet SHA256SUMS

[[ -x bin/ghidrasql ]] || chmod +x bin/ghidrasql
./bin/ghidrasql --version

echo "Seed contents verified against SHA256SUMS."
