#!/usr/bin/env bash
# Assemble the prebuilt seed asset.
#
# All the logic lives here rather than in the workflow so it can be run and debugged
# locally (WSL/Linux) exactly as CI runs it. The workflow is a thin wrapper.
#
# Usage:
#   build-seed.sh --cli <path> --extension <zip> --skills <dir> [--out dist] [--version X.Y.Z]
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"
# shellcheck disable=SC1091
source "$script_dir/versions.env"

cli="" extension="" skills="" out="$repo_root/dist" version=""
while (( $# )); do
    case "$1" in
        --cli)       cli="$2"; shift 2 ;;
        --extension) extension="$2"; shift 2 ;;
        --skills)    skills="$2"; shift 2 ;;
        --out)       out="$2"; shift 2 ;;
        --version)   version="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

for required in cli extension skills; do
    [[ -n "${!required}" ]] || { echo "missing --$required" >&2; exit 2; }
done
[[ -f "$cli" ]]       || { echo "CLI not found: $cli" >&2; exit 2; }
[[ -f "$extension" ]] || { echo "extension zip not found: $extension" >&2; exit 2; }
[[ -d "$skills" ]]    || { echo "skills tree not found: $skills" >&2; exit 2; }
[[ -n "$version" ]]   || version="$(tr -d '[:space:]' < "$repo_root/VERSION")"

# The asset name is a CONTRACT: agents fetch
#   .../releases/latest/download/ghidrasql-seed-linux-x86_64.zip
# which only resolves while the name stays identical across releases. Renaming it
# silently breaks every consumer, so it is deliberately not version-stamped.
asset="ghidrasql-seed-linux-x86_64"
stage="$out/$asset"
rm -rf "$stage"
mkdir -p "$stage"/{bin,extensions,scripts,prompts,patches,licenses}

install -m 0755 "$cli" "$stage/bin/ghidrasql"
cp "$extension" "$stage/extensions/LibGhidraHost-ghidra-$GHIDRA_VERSION.zip"
cp -a "$skills/." "$stage/ghidrasql-skills/"
cp "$repo_root/prompts/ghidrasql_agent.md" "$stage/prompts/"
cp "$script_dir"/{env.sh,bootstrap-runtime.sh,run-headless.sh,query.sh,shutdown.sh,verify-seed.sh,verify-host.sh,self-test.sh} \
   "$stage/scripts/"
cp "$script_dir/versions.env" "$stage/scripts/"
cp "$script_dir/patches/ghidra-launch-no-dev-fd.patch" "$stage/patches/"
cp "$script_dir/START-HERE.md" "$stage/"
cp "$script_dir/chatgpt-work-install-prompt.md" "$stage/"
cp "$repo_root/LICENSE" "$stage/licenses/ghidrasql-LICENSE"
[[ -f "$skills/LICENSE" ]] && cp "$skills/LICENSE" "$stage/licenses/ghidrasql-skills-LICENSE"
chmod +x "$stage/scripts/"*.sh

# Provenance: this is what makes the asset auditable and marks it CI-produced rather
# than something built by hand on somebody's laptop.
{
    echo "# Provenance"
    echo
    echo "| Field | Value |"
    echo "|---|---|"
    echo "| ghidrasql version | $version |"
    echo "| built by | ${GITHUB_WORKFLOW:-local build} |"
    echo "| run | ${GITHUB_RUN_ID:+${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}}${GITHUB_RUN_ID:-not a CI run} |"
    echo "| ghidrasql commit | ${GHIDRASQL_SHA:-$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || echo unknown)} |"
    echo "| libghidra commit | ${LIBGHIDRA_SHA:-unknown} |"
    echo "| skills commit | ${SKILLS_SHA:-unknown} |"
    echo "| built on | $(uname -srm) |"
    echo "| pinned Ghidra | $GHIDRA_VERSION ($GHIDRA_SHA256) |"
    echo "| pinned JDK | $JDK_VERSION ($JDK_SHA256) |"
    echo
    echo "Ghidra and the JDK are NOT bundled. \`scripts/bootstrap-runtime.sh\` downloads"
    echo "the two archives above from their official releases and verifies both digests"
    echo "before use."
} > "$stage/PROVENANCE.md"

# Hash everything except the manifest itself, so verify-seed.sh can check the contents.
( cd "$stage" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
    | xargs -0 sha256sum > SHA256SUMS )

( cd "$out" && rm -f "$asset.zip" && \
  if command -v zip >/dev/null 2>&1; then
      zip -qXr "$asset.zip" "$asset"
  else
      python3 - "$asset" <<'PY'
import os, sys, zipfile
root = sys.argv[1]
with zipfile.ZipFile(root + ".zip", "w", zipfile.ZIP_DEFLATED) as z:
    for dirpath, _, files in os.walk(root):
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            info = zipfile.ZipInfo(os.path.relpath(full, ".").replace(os.sep, "/"))
            info.compress_type = zipfile.ZIP_DEFLATED
            # Preserve the executable bit; the scripts and the CLI are useless without it.
            info.external_attr = (os.stat(full).st_mode & 0xFFFF) << 16
            with open(full, "rb") as fh:
                z.writestr(info, fh.read())
PY
  fi )

echo "seed: $out/$asset.zip ($(du -h "$out/$asset.zip" | cut -f1))"
