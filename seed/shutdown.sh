#!/usr/bin/env bash
# Ask the server to stop, then WAIT for it to actually exit.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck disable=SC1091
source "$script_dir/env.sh"

port="${1:-${GHIDRASQL_PORT:-8081}}"
pid_file="$GHIDRASQL_KIT_ROOT/var/run/ghidrasql-$port.pid"

curl -fsS -X POST "http://127.0.0.1:$port/shutdown" >/dev/null 2>&1 || true

# /shutdown answers in about 150 ms, while the Java host is still flushing the project
# per its --shutdown policy. Trusting that response and reusing the project directory
# immediately is how you end up with a half-written project and stray lock files, so
# wait for the process itself.
if [[ -f "$pid_file" ]]; then
    server_pid="$(cat "$pid_file")"
    for _ in $(seq 1 120); do
        kill -0 "$server_pid" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "$server_pid" 2>/dev/null; then
        echo "ghidrasql (pid $server_pid) is still running after 120s." >&2
        exit 1
    fi
    rm -f "$pid_file"
fi

# A clean exit leaves no locks behind. Report them rather than deleting: a lock with a
# live owner means something is still running, and silently removing it corrupts state.
mapfile -t stale < <(find "$GHIDRASQL_KIT_ROOT/var/projects" \
    \( -name '*.lock' -o -name '*.lock~' \) -print 2>/dev/null || true)
if (( ${#stale[@]} > 0 )); then
    echo "Warning: lock files remain (delete them only if no ghidrasql/java is running):" >&2
    printf '  %s\n' "${stale[@]}" >&2
fi

echo "ghidrasql on port $port has stopped."
