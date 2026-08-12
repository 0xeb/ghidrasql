#!/usr/bin/env bash
# Run one SQL statement (or a multi-statement body) against a running server.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck disable=SC1091
source "$script_dir/env.sh"

if (( $# < 1 || $# > 2 )); then
    echo "Usage: $0 'SQL' [PORT]" >&2
    exit 2
fi

port="${2:-${GHIDRASQL_PORT:-8081}}"
curl -fsS -X POST "http://127.0.0.1:$port/query" --data "$1"
echo
