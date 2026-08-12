#!/usr/bin/env bash
# Import + analyze a binary and leave a SQL HTTP server running.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck disable=SC1091
source "$script_dir/env.sh"

if (( $# < 1 || $# > 4 )); then
    echo "Usage: $0 BINARY [PROJECT_DIR] [PROJECT_NAME] [PORT]" >&2
    exit 2
fi

target="$1"
project_dir="${2:-$GHIDRASQL_KIT_ROOT/var/projects/default}"
project_name="${3:-analysis}"
port="${4:-${GHIDRASQL_PORT:-8081}}"

if [[ ! -r "$target" ]]; then
    echo "Target is not readable: $target" >&2
    exit 2
fi

# Ghidra's headless launcher rejects a relative path and any element starting with '.'
# ("Path element starting with '.' is not permitted"), so resolve both to absolute.
target="$(cd -- "$(dirname -- "$target")" && pwd -P)/$(basename -- "$target")"
mkdir -p "$project_dir"
project_dir="$(cd -- "$project_dir" && pwd -P)"

log_file="$GHIDRASQL_KIT_ROOT/var/log/ghidrasql-$port.log"
pid_file="$GHIDRASQL_KIT_ROOT/var/run/ghidrasql-$port.pid"

if curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
    echo "A ghidrasql HTTP server is already listening on port $port." >&2
    exit 1
fi

nohup "$GHIDRASQL_KIT_ROOT/bin/ghidrasql" \
    --ghidra "$GHIDRA_INSTALL_DIR" \
    --binary "$target" \
    --project "$project_dir" \
    --project-name "$project_name" \
    --analyze --http --port "$port" --max-runtime 0 \
    >"$log_file" 2>&1 &

server_pid=$!
printf '%s\n' "$server_pid" >"$pid_file"

# Analysis time scales with the binary, so poll for readiness instead of sleeping.
# Watch the process too: if it dies, say so immediately with its log rather than
# burning the full timeout.
for _ in $(seq 1 150); do
    if curl -fsS "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
        echo "ghidrasql ready: http://127.0.0.1:$port"
        echo "Log:     $log_file"
        echo "Project: $project_dir/$project_name"
        exit 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        echo "ghidrasql exited before becoming ready." >&2
        tail -n 120 "$log_file" >&2 || true
        wait "$server_pid" || true
        exit 1
    fi
    sleep 2
done

echo "Timed out waiting for ghidrasql readiness; see $log_file" >&2
kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
exit 1
