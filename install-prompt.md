# ghidrasql Install Prompt (for AI Agents)

Self-contained runbook to stand up `ghidrasql` from zero. Each step
ends with an explicit verification gate. **If a gate fails, follow the
remediation note before continuing.** Do not skip gates — every later
step assumes the earlier ones succeeded.

For human users: see `README.md` instead. For SQL surface reference
once the server is up: see `prompts/ghidrasql_agent.md`.

---

## Step 0 — Preflight (verify dependencies)

| Check | Command | Expected | Remediation |
|-------|---------|----------|-------------|
| JDK 21 | `java -version` | `21` in output | Install Eclipse Adoptium 21: <https://adoptium.net/temurin/releases/?version=21> |
| CMake ≥ 3.20 | `cmake --version` | major.minor ≥ 3.20 | Install from <https://cmake.org/download/> |
| C++20 compiler | `cl /?` (Win) or `g++ --version` / `clang++ --version` | any 2022+ MSVC, GCC 12+, or Clang 15+ | Install Visual Studio 2022, or `apt install build-essential` / `xcode-select --install` |
| Git | `git --version` | any modern | <https://git-scm.com/downloads> |
| Gradle ≥ 8 | `gradle --version` | major ≥ 8 | <https://gradle.org/install/> (or rely on the wrapper if the libghidra repo provides one) |
| Python ≥ 3.10 | `python --version` | major.minor ≥ 3.10 | <https://www.python.org/downloads/> |

**Environment note**: if `GHIDRA_INSTALL_DIR` is already set in your
shell, the `ghidrasql` CLI auto-fills `--ghidra` from it and **rejects
`--url` as conflicting**. When attaching to a running host with
`--url`, prefix the invocation with `unset GHIDRA_INSTALL_DIR;` or use
`env -u GHIDRA_INSTALL_DIR ghidrasql --url ...`. The runbook uses
`--ghidra` throughout, so leaving the env var set is fine for the
bootstrap path itself.

---

## Step 1 — Acquire Ghidra distribution

Download Ghidra 12.1+ from the official release page:
<https://github.com/NationalSecurityAgency/ghidra/releases>

Pick a release with a published SHA-256. Verify after download:

```bash
sha256sum ghidra_*_PUBLIC.zip   # compare to release-page hash
```

Extract to a stable location and set `GHIDRA_INSTALL_DIR`:

```bash
# Windows (PowerShell)
$env:GHIDRA_INSTALL_DIR = "C:/ghidra_dist/ghidra_12.1_PUBLIC"

# POSIX
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1_PUBLIC
```

**Gate**:
```bash
test -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
ls "$GHIDRA_INSTALL_DIR/Ghidra/Framework"   # non-empty
```

If the gate fails: re-extract and confirm `GHIDRA_INSTALL_DIR` points
at the directory that *contains* `support/`, `Ghidra/`, `ghidraRun*`.

---

## Step 2 — Clone repos

```bash
git clone https://github.com/0xeb/libghidra.git
git clone https://github.com/0xeb/ghidrasql.git
```

**Gate**:
```bash
test -d libghidra/.git && test -d ghidrasql/.git
test -f libghidra/README.md && test -f ghidrasql/README.md
```

---

## Step 3 — Build and install LibGhidraHost extension

This installs the Ghidra extension that ghidrasql talks to over RPC.

```bash
cd libghidra/ghidra-extension
gradle installExtension -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"
cd ../..
```

**Gate**:
```bash
ls "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/LibGhidraHost"
test -f "$GHIDRA_INSTALL_DIR/Ghidra/Extensions/LibGhidraHost/ghidra_scripts/LibGhidraHeadlessServer.java"
```

If the gate fails: try `gradle clean buildExtension`, then copy the
produced `.zip` from `dist/` into `$GHIDRA_INSTALL_DIR/Extensions/Ghidra/`.
Ghidra unpacks it on next launch.

---

## Step 4 — Build ghidrasql

**Windows / MSVC**:
```bash
cd ghidrasql
cmake -B build -G "Visual Studio 17 2022" \
      -DGHIDRASQL_LIBGHIDRA_DIR=../libghidra/cpp
cmake --build build --config Release
```

**Linux / macOS**:
```bash
cd ghidrasql
cmake -B build -DGHIDRASQL_LIBGHIDRA_DIR=../libghidra/cpp \
      -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

**Gate**:
```bash
# Windows
test -f ghidrasql/build/bin/Release/ghidrasql.exe
ghidrasql/build/bin/Release/ghidrasql.exe --help | head -5

# POSIX
test -x ghidrasql/build/bin/ghidrasql
ghidrasql/build/bin/ghidrasql --help | head -5
```

`--help` should print usage starting with `ghidrasql [options]`.

---

## Step 5 — Pick a test binary

Use a small, universally available binary so the agent can finish the
end-to-end check without extra setup:

| Platform | Suggested test binary |
|----------|------------------------|
| Windows  | `C:/Windows/System32/notepad.exe` |
| Linux    | `/bin/ls` |
| macOS    | `/bin/ls` |

Or compile a trivial one:

```bash
echo 'int main(void){return 42;}' > /tmp/tinybin.c
cc -o /tmp/tinybin /tmp/tinybin.c
```

**Gate**: the test binary path you chose exists and is readable.

---

## Step 6 — Run ghidrasql in background HTTP mode

This starts Ghidra headlessly, imports the test binary, analyzes it,
and exposes a SQL HTTP endpoint at `http://127.0.0.1:8081/query`.

```bash
# Windows
ghidrasql/build/bin/Release/ghidrasql.exe \
  --ghidra "$GHIDRA_INSTALL_DIR" \
  --binary <test-binary> \
  --project /tmp/ghidrasql-bootstrap --project-name boot \
  --analyze \
  --http --port 8081 --max-runtime 0 &

# POSIX
ghidrasql/build/bin/ghidrasql \
  --ghidra "$GHIDRA_INSTALL_DIR" \
  --binary <test-binary> \
  --project /tmp/ghidrasql-bootstrap --project-name boot \
  --analyze \
  --http --port 8081 --max-runtime 0 &
```

The headless host prints `LIBGHIDRA_HEADLESS_READY` to stdout when the
RPC layer is up. Analysis can take additional time depending on binary
size. Use the HTTP gate below as the authoritative readiness signal.

**Gate**: poll `/health` until 200, then `/query` returns success.
`/health` is the dumb liveness probe — it always returns 200 once the
HTTP listener is up; it does not probe the query worker. For readiness
(is the query worker actually responsive?), use `/health/deep` — it
returns 503 when an in-flight query has been wedged longer than the
configured threshold.

```bash
# Wait for the HTTP server to start (polls every 2s, max ~3 min)
until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/health)" = "200" ]; do
  sleep 2
done
```

**`--max-runtime 0` disables the auto-exit timer.** If you set a
positive value, the server prints `LIBGHIDRA_HEADLESS_MAX_RUNTIME_REACHED`
and exits when it elapses.

---

## Step 7 — Smoke-test queries

```bash
# Program metadata
curl -s -X POST http://127.0.0.1:8081/query \
  --data "SELECT * FROM db_info;"

# Function count
curl -s -X POST http://127.0.0.1:8081/query \
  --data "SELECT COUNT(*) AS n FROM funcs;"

# A few function names (sanity check)
curl -s -X POST http://127.0.0.1:8081/query \
  --data "SELECT name, printf('0x%X', address) AS addr FROM funcs ORDER BY size DESC LIMIT 5;"
```

**Gate**:
- `db_info` returns one row with non-empty `language_id` (e.g.
  `x86:LE:64:default`) and a numeric `revision`.
- `funcs` count > 0.
- The third query returns 5 rows with `name` and `addr`.

If `funcs` count is 0:
- Check the headless log on stdout for parse errors on the binary.
- Try a different test binary (e.g. a freshly built `tinybin`).
- Confirm `--analyze` was passed; without it, raw imports may have
  zero functions.

---

## Step 8 — Clean shutdown

```bash
curl -X POST http://127.0.0.1:8081/shutdown
```

`/shutdown` returns `{"success":true}` once the HTTP listener is
stopping. The Java host then applies the launch-time `--shutdown`
policy (default `save`) and exits. **For large pending state this can
take tens of seconds.** Wait for both `java` and `ghidrasql` to leave
the process list before reusing the project directory.

```bash
# Windows
tasklist | findstr /I "java.exe ghidrasql.exe"   # expect: empty
ls /tmp/ghidrasql-bootstrap                       # expect: only boot.gpr and boot.rep/

# POSIX
pgrep -f 'ghidrasql|java'    # expect: empty
ls /tmp/ghidrasql-bootstrap   # expect: only boot.gpr and boot.rep/
```

**Gate**: process list contains neither `java` nor `ghidrasql`, and
the project directory contains only `<name>.gpr` and `<name>.rep/` —
no `*.lock` / `*.lock~` files.

---

## Where to go next

- **SQL surface reference** (tables, views, functions, write
  operations, query patterns): `prompts/ghidrasql_agent.md`.
- **Human quickstart**: `README.md`.
- **Skill bundle for analysis workflows** (decompile, annotate,
  cross-reference, type import, …): <https://github.com/0xeb/ghidrasql-skills>.
- **Re-attach to a running host** (skip Step 6's launch flow):
  `unset GHIDRA_INSTALL_DIR; ghidrasql --url http://127.0.0.1:18080`.

---

## Lessons baked in (rationale, do not skip)

These are non-obvious gotchas that have cost real time. The runbook
already routes around them; this section explains why so the agent
recognizes the symptoms.

- **`GHIDRA_INSTALL_DIR` env var auto-fills `--ghidra`.** When the
  user wants to attach to an existing host with `--url`, the CLI
  fails with `error: --ghidra and --url are mutually exclusive` and
  no hint about the env var. Unset per-invocation.
- **`POST /shutdown` returns success ~150 ms in.** After the listener
  stops, the Java host flushes the project per the launch-time
  `--shutdown save|discard|none` policy. Trust the response and just
  wait for the processes to exit.
- **Force-killing leaves orphaned `*.lock` / `*.lock~` files** in the
  project directory. If you find them after a previous crash and no
  `java` is running, delete both before launching again.
- **HTTP `/query` accepts multi-statement bodies.** Each response wraps
  per-statement results in a `results` array; single-statement bodies
  use the same shape with `statement_count: 1`. If a statement errors,
  later statements are not executed and `success` is `false` with
  `results[]` carrying the partial run.
- **Decompiler-backed tables (`pseudocode`, `decomp_lvars`,
  `decomp_tokens`) must be filtered by `func_addr`.** An unbounded
  query decompiles every function in the binary and can hang the
  server under load. The skills bundle enforces this rule across
  every analysis recipe.
