# ghidrasql install prompt (for AI agents)

Runbook to get from nothing to answering SQL questions about a binary. **Prefer the
prebuilt path below** — it needs no compiler, no CMake and no Gradle, and takes minutes
instead of the better part of an hour. Every step ends with a gate; if a gate fails,
apply its remediation before continuing.

For the SQL surface once the server is up, read `prompts/ghidrasql_agent.md`.

---

## Path A — prebuilt seed (do this)

### A0 — Preflight

| Check | Command | Expected | Remediation |
|---|---|---|---|
| Linux x86-64 | `uname -sm` | `Linux x86_64` | Use Path B on other platforms |
| curl | `command -v curl` | a path | `apt-get install -y curl` |
| tar + sha256sum | `command -v tar sha256sum` | two paths | part of coreutils/tar |
| unzip **or** python3 | `command -v unzip \|\| command -v python3` | a path | either one works; the seed falls back to python3 |

No JDK, compiler, CMake or Gradle is required on this path.

### A1 — Download and unpack

This URL always resolves to the newest release; no tag lookup or API call:

```bash
curl -L --retry 5 --fail -o ghidrasql-seed.zip \
  https://github.com/0xeb/ghidrasql/releases/latest/download/ghidrasql-seed-linux-x86_64.zip
unzip -q ghidrasql-seed.zip || python3 -m zipfile -e ghidrasql-seed.zip .
cd ghidrasql-seed-linux-x86_64
```

**Gate**: `./scripts/verify-seed.sh` succeeds — contents match `SHA256SUMS` and
`bin/ghidrasql --version` prints a version.
*If it fails*: the download was truncated (proxied transports do this); re-run the
`curl`, which resumes.

### A2 — Bootstrap the runtime (once)

```bash
./scripts/bootstrap-runtime.sh
```

Downloads the pinned Ghidra and Temurin JDK, verifies both SHA-256 digests, installs the
prebuilt `LibGhidraHost` extension. Compiles nothing.

**Gate**: it ends with `Runtime verified: ...`.
*If it fails on a download*: re-run — `curl --continue-at` resumes a partial file.
*If it fails on the extension*: confirm `extensions/LibGhidraHost-ghidra-*.zip` exists.

### A3 — Analyze a binary

```bash
./scripts/run-headless.sh /bin/ls
```

**Gate**: prints `ghidrasql ready: http://127.0.0.1:8081`.
*If it exits early*: the script prints the tail of `var/log/ghidrasql-8081.log` — read it.
Analysis time scales with the binary; the script polls rather than assuming.

### A4 — Query

```bash
./scripts/query.sh 'SELECT COUNT(*) AS n FROM funcs;'
./scripts/query.sh "SELECT name, printf('0x%X', addr) AS addr FROM funcs ORDER BY size DESC LIMIT 10;"
```

**Gate**: the function count is > 0 and the second query returns rows.
*If the count is 0*: the binary may have imported without analysis — check the log.

### A5 — Stop

```bash
./scripts/shutdown.sh
```

**Gate**: prints that the server stopped and warns about no lock files.

Shortcut for all of the above: `./scripts/self-test.sh`.

---

## Path B — build from source (fallback)

Only when no seed exists for your platform. This is the slow path: it needs JDK 21,
CMake ≥ 3.26, a C++20 compiler, Gradle ≥ 8.5 and Git, and it compiles a large dependency
stack.

1. Install a Ghidra distribution and set `GHIDRA_INSTALL_DIR` to the directory
   containing `support/`, `Ghidra/`, `ghidraRun*`.
   **Gate**: `test -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`.
2. `git clone https://github.com/0xeb/libghidra.git` and
   `git clone https://github.com/0xeb/ghidrasql.git`.
3. Build and install the extension:
   `cd libghidra/ghidra-extension && gradle installExtension -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"`.
   **Gate**: `$GHIDRA_INSTALL_DIR/Ghidra/Extensions/LibGhidraHost/extension.properties` exists.
4. Build the CLI:
   `cmake -B build -DGHIDRASQL_LIBGHIDRA_DIR=../libghidra/cpp -DCMAKE_BUILD_TYPE=Release && cmake --build build -j`.
   **Gate**: `build/bin/ghidrasql --help` prints usage.
5. Run it directly:
   `ghidrasql --ghidra "$GHIDRA_INSTALL_DIR" --binary /bin/ls --project /tmp/gs --project-name boot --analyze --http --port 8081`,
   then `curl -X POST http://127.0.0.1:8081/query --data 'SELECT COUNT(*) FROM funcs;'`.

---

## Lessons baked in (rationale — do not skip)

These cost real sessions real time. The scripts already route around them; this is so
you recognise the symptoms.

- **`GHIDRA_INSTALL_DIR` auto-fills `--ghidra`,** so passing `--url` fails with
  "mutually exclusive" and no hint about the env var. Use
  `env -u GHIDRA_INSTALL_DIR ghidrasql --url ...` to attach to a running host.
- **`POST /shutdown` returns in ~150 ms** while the Java host is still flushing the
  project. Wait for the process to exit before reusing the project directory.
- **Force-killing strands `*.lock` / `*.lock~`.** Delete them only once no `ghidrasql`
  or `java` process is alive.
- **Decompiler-backed tables must be filtered by `func_addr`** (`pseudocode`,
  `decomp_lvars`, `decomp_tokens`). Unbounded, they decompile the whole program.
- **`--project` must be an absolute path** with no element starting with `.`, or
  Ghidra's launcher rejects it.
- **Multi-statement bodies are allowed** on `/query`; results come back in a `results`
  array and a failing statement stops the ones after it.

### Constrained VM notes

Seen on sandboxed agent VMs; the seed handles each one, but recognise them:

- **No `/dev/fd`** breaks Ghidra's launcher, which uses bash process substitution. The
  bootstrap probes for this and patches the launcher only when needed.
- **No usable `/tmp`** breaks Java temp files. The scripts point `TMPDIR` and
  `-Djava.io.tmpdir` inside the seed directory.
- **A broken system Java** (`libjli.so` not found) is why the scripts set `JAVA_HOME`
  and put the JDK's `lib` and `lib/server` on the loader path explicitly.
- **Proxied or throttled transport** truncates large downloads. Every fetch retries and
  resumes; re-running the bootstrap is safe and continues where it stopped.
- **Gradle may not reach Maven Central** even when plain HTTP works, which breaks the
  extension build in Path B step 3 — the observed workaround was a small, checksum-
  verified local Maven repository holding `protobuf-java` (matching the version the
  committed stubs declare) plus an offline Gradle run. Path A avoids this entirely: the
  extension ships prebuilt, so no dependency resolution happens on the VM at all.
- **Constrained CPU/memory** can truncate a parallel compile. That only affects Path B —
  drop to a serial build if you see a truncated assembler input.
