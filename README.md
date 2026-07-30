<p align="center">
  <img src="docs/logo.jpg" alt="ghidrasql logo" width="360">
</p>

# ghidrasql

SQL interface for Ghidra program databases. Query functions, cross-references, types, decompilation output, and more using standard SQL.

## Install with an AI agent (recommended)

The fastest way to get `ghidrasql` running end-to-end is to point an AI coding
agent (Claude Code, Cursor, Codex, Aider, etc.) at the bundled installer
prompt:

> [`install-prompt.md`](install-prompt.md)

It is a self-contained runbook with explicit verification gates at every
step — preflight checks, building `libghidra`, installing the
`LibGhidraHost` Ghidra extension, building `ghidrasql`, and a first live
query. Hand it to your agent and let it drive the install; intervene only
if a gate reports a failure.

You will also want the companion **[ghidrasql-skills][gss]** plugin pack —
a set of focused agent skills (`analysis`, `annotations`, `connect`,
`debugger`, `decompiler`, `disassembly`, `functions`, `re-source`, `types`,
`xrefs`, `ui-context`, `data`, …) that turn `ghidrasql` into a usable
SQL-driven RE workflow inside your agent. Install it the same way: point
the agent at the skills repo and let it register the skills.

[gss]: https://github.com/0xeb/ghidrasql-skills

If you would rather drive the build yourself, see **Get Running** below.

## Get Running

### Alpha Quickstart

For the current alpha, the most reliable path is:

1. Install `LibGhidraHost` from `libghidra/ghidra-extension`.
2. Start a live `libghidra` host from Ghidra GUI or headless.
3. Build `ghidrasql` in `Release`.
4. First connect with `ghidrasql --url http://127.0.0.1:18080 -q "SELECT COUNT(*) FROM funcs"`.
5. Then exercise structured annotation flows by querying `decomp_lvars` / `function_locals`,
   capturing the canonical `local_id`, and using that exact value for rename/retype updates.

### Prerequisites

- [Ghidra](https://ghidra-sre.org/) distribution (12.1+) and JDK 21
- [libghidra](https://github.com/0xeb/libghidra) -- provides the `LibGhidraHost` extension and C++ SDK
- C++20 compiler (Visual Studio 2022, GCC 12+, or Clang 15+)
- CMake 3.26+
- Gradle (for building the Ghidra extension)

### 1. Clone both repos

```bash
git clone https://github.com/0xeb/libghidra.git
git clone https://github.com/0xeb/ghidrasql.git
```

### 2. Install the LibGhidraHost extension

```bash
cd libghidra/ghidra-extension
gradle installExtension -PGHIDRA_INSTALL_DIR=/path/to/ghidra_dist
cd ../../..
```

**Enable the plugin in the Ghidra GUI** — only needed for the *connect-to-GUI* workflow
(`ghidrasql --url …`); the headless `--binary` path does not need it.

1. In the CodeBrowser, open **File → Configure**.
2. In the **Ghidra Core** group click **Configure**, search for **libghidra**, check
   **LibGhidraHostPlugin**, then **OK**.
3. Start the host from **Tools → libghidra Host → Start Server…** (default port `18080`;
   **Stop Server** and **Status** are in the same menu).

If the plugin doesn't appear right after installing the extension, clear Ghidra's OSGi
bundle cache (`~/Library/ghidra/<version>/osgi/` on macOS, `~/.ghidra/.../osgi/` on
Linux/Windows) and restart Ghidra.

### 3. Build ghidrasql

```bash
cd ghidrasql
cmake -B build -G "Visual Studio 17 2022" -DGHIDRASQL_LIBGHIDRA_DIR=../libghidra/cpp
cmake --build build --config Release
```

`ghidrasql` only needs `libghidra`'s HTTP client, not its offline/local backend, so
you do not need to set `GHIDRA_SOURCE_DIR` for this build.

`GHIDRASQL_LIBGHIDRA_DIR` may point either to:
- a `libghidra/cpp/` source tree, or
- a `libghidra` install prefix / package directory that provides `find_package(libghidra CONFIG)`

Output: `build/bin/Release/ghidrasql.exe`

### 4. Run your first query

```bash
ghidrasql --ghidra /path/to/ghidra_dist \
  --binary target.exe \
  --project ./projects --project-name demo \
  -q "SELECT name, addr, size FROM funcs ORDER BY size DESC LIMIT 10"
```

This imports the binary, runs full Ghidra analysis, executes your query, saves the project, and shuts down. First run takes a few minutes (analysis); subsequent runs with the same `--project` reuse the existing analysis.

> **Input file**: `--binary <path>` accepts a raw binary (`.exe`/`.dll`/firmware/etc.) and runs Ghidra's headless importer on it. You do **not** need to pre-build a Ghidra project — `ghidrasql --binary raw.exe --project ./proj ...` creates the project and imports the program in one shot. To reopen an already-imported program in an existing project, use `--program <name>` instead of `--binary <path>`.
>
> **Library loading**: imports **skip loading external system libraries by default** (kernel32, CRT, …) so imports stay fast. Imports referenced by name still resolve; only imports-by-*ordinal* show as ordinals rather than names. Pass **`--load-libraries`** to load and link them (slower, and pulls the libraries into the project).

## Quick Start Examples

```bash
# One-shot query (headless: import, analyze, query, shutdown)
ghidrasql --ghidra /path/to/ghidra_dist \
  --binary target.exe --project ./proj --project-name demo \
  -q "SELECT name, addr FROM funcs LIMIT 10"

# Interactive REPL
ghidrasql --ghidra /path/to/ghidra_dist \
  --binary target.exe --project ./proj --project-name demo -i

# Reopen existing project (no re-analysis)
ghidrasql --ghidra /path/to/ghidra_dist \
  --project ./proj --project-name demo --program target.exe --no-analyze -i

# Connect to already-running Ghidra (GUI with LibGhidraHost enabled)
ghidrasql --url http://127.0.0.1:18080 -i

# Start an HTTP API server for programmatic access
ghidrasql --ghidra /path/to/ghidra_dist \
  --binary target.exe --project ./proj --project-name demo \
  --http --port 8081

# Then query it: curl -X POST http://localhost:8081/query -d "SELECT * FROM funcs LIMIT 5"

# Managed HTTP sessions can import/list/open project programs without restart
curl http://localhost:8081/project/programs
curl -X POST http://localhost:8081/project/open --json '{"program_path":"/target.exe"}'
```

## Example Queries

```sql
-- Functions sorted by size
SELECT name, addr, size FROM funcs ORDER BY size DESC LIMIT 20;

-- Cross-references to an address
SELECT * FROM xrefs WHERE to_addr = 0x401000;

-- String references
SELECT * FROM string_refs WHERE string_value LIKE '%password%';

-- Call graph
SELECT src_func_name, dst_func_name FROM callgraph_edges LIMIT 50;

-- Decompile a function
SELECT * FROM pseudocode WHERE func_addr = 0x401000;

-- Struct types with members
SELECT t.name AS type_name, m.member_name, m.member_type, m.offset
FROM types t JOIN type_members m ON t.name = m.type_name
WHERE t.kind = 'struct';

-- Memory hexdump
SELECT * FROM memory_hexdump WHERE addr >= 0x401000 LIMIT 16;

-- Rename a function (write-through to Ghidra)
UPDATE funcs SET name = 'my_main' WHERE addr = 0x401000;

-- Rewrite a function signature
UPDATE funcs SET prototype = 'int main(int argc, char** argv)' WHERE addr = 0x401000;

-- Save changes to the Ghidra project
SELECT save_database();
```

## CLI Reference

### Connection (pick one)

| Flag | Description |
|------|-------------|
| `--ghidra <path>` | Ghidra distribution path (headless mode) |
| `--url <url>` | Connect to running LibGhidraHost |

### Actions

| Flag | Description |
|------|-------------|
| `-q, --query <sql>` | Execute query and exit |
| `-f, --file <path>` | Execute SQL script and exit |
| `-i, --interactive` | Interactive REPL (default when no action) |
| `--http`, `--serve` | Start HTTP API server |

### Program/project

| Flag | Description |
|------|-------------|
| `--binary <path>` | Raw binary (`.exe`/`.dll`/firmware/etc.) to import via headless analysis; repeatable for multi-binary projects. Imports skip external system libraries by default (see `--load-libraries`) |
| `--program <name>` | Existing program inside the project — use to reopen what was already imported; for fresh imports use `--binary` |
| `--project <dir>` | Project directory |
| `--project-name <name>` | Project name |
| `--analyze` | Run analysis (default in headless) |
| `--no-analyze` | Skip analysis |
| `--load-libraries` | Load/link external system libraries during `--binary` import (ordinal→name resolution). Off by default — slower, and pulls kernel32/CRT into the project |
| `--readonly` | Read-only session |

### Server/network

| Flag | Description |
|------|-------------|
| `--port <n>` | HTTP port (default: 8081) |
| `--bind <addr>` | Bind address (default: 127.0.0.1) |
| `--auth <token>` | Bearer auth token |

### Lifecycle (headless)

| Flag | Description |
|------|-------------|
| `--shutdown <mode>` | save\|discard\|none (default: save; discard when --readonly) |
| `--keep-host` | Don't auto-shutdown after query |
| `--max-runtime <sec>` | Host lifetime bound (0=disable; default: 0 for `--http` serve mode, 600 for one-shot `-q`/`-f`/`-i`) |
| `--fresh` | Delete existing project first |
| `--auto-save <n>` | Save every N mutations (0=disabled) |

### REPL commands

| Command | Description |
|---------|-------------|
| `.tables` | List all tables and views |
| `.schema <table>` | Show table schema |
| `.info` | Show program metadata |
| `.save` | Save pending changes |
| `.discard` | Discard pending changes |
| `.refresh` | Refresh data from Ghidra |
| `.http` / `.http start` / `.http stop` | Control HTTP server |
| `.help` | Show help |
| `.quit` | Exit |

## SQL Surface

65 public tables and 81 views covering every aspect of a Ghidra program database.

### Tables

| Category | Tables |
|----------|--------|
| **Functions** | `funcs`, `function_params`, `function_locals`, `function_frames`, `function_chunks`, `function_metrics`, `stack_vars`, `register_vars`, `tail_calls` |
| **Code** | `instructions`, `instruction_operands`, `blocks`, `cfg_edges`, `loops`, `switch_tables`, `dominators`, `post_dominators` |
| **References** | `xrefs`, `call_edges`, `function_calls`, `xref_index` |
| **Symbols** | `names`, `imports`, `entries`, `strings`, `equates`, `constants` |
| **Memory** | `segments`, `memory_blocks`, `bytes`, `byte_search` |
| **Types** | `types`, `type_members`, `type_enums`, `type_enum_members`, `type_unions`, `type_aliases`, `signatures` |
| **Decompiler** | `pseudocode`, `decomp_lvars`, `decomp_tokens`, `decomp_comments`, `pcode_ops`, `pcode_varnodes` |
| **Comments** | `comments` |
| **Data** | `data_items`, `relocations` |
| **Search** | `text_index`, `search_index` |
| **Program** | `program_options`, `analysis_passes`, `transactions`, `project_properties`, `breakpoints` |
| **Meta** | `sql_capabilities`, `parity_findings`, `perf_benchmarks`, `live_meta`, `binary` |

### Selected Views

| Category | Views |
|----------|-------|
| **Functions** | `functions`, `function_signatures`, `function_metrics_ranked`, `function_metrics_scored` |
| **Call graph** | `callgraph_edges`, `callers`, `callees`, `function_call_stats` |
| **References** | `string_refs`, `string_hotspots`, `xref_paths` |
| **Memory** | `memory_hexdump`, `memory_layout` |
| **Types** | `types_v_structs`, `types_v_unions`, `types_v_enums`, `types_v_typedefs`, `type_layout` |
| **Decompiler** | `decompiler_listing`, `ctree`, `ctree_v_calls`, `ctree_v_loops`, `ctree_v_ifs`, `ir_ops`, `ir_operands`, `ir_maturities`, `ir_v_*` |

Use `.tables` in the REPL to see the full list, or `SELECT name FROM sqlite_master ORDER BY name`.

### Write Operations

Write-through mutations are supported:

```sql
UPDATE funcs SET name = 'new_name' WHERE addr = 0x401000;
UPDATE comments SET comment = 'note' WHERE addr = 0x401000;
DELETE FROM comments WHERE addr = 0x401000;
UPDATE signatures SET prototype = 'int foo(int a, int b)' WHERE entry_point = 0x401000;
UPDATE data_items SET data_type = 'int' WHERE addr = 0x402000;
SELECT save_database();
```

For local-variable updates, query the canonical `local_id` first and reuse it verbatim:

```sql
SELECT local_id, role, name, type
FROM decomp_lvars
WHERE func_addr = 0x401000;

UPDATE decomp_lvars
SET name = 'result_value'
WHERE func_addr = 0x401000 AND local_id = '...exact local_id from query...';

UPDATE function_locals
SET local_type = 'uint64_t'
WHERE func_addr = 0x401000 AND local_id = '...exact local_id from query...';
```

## Architecture

```
ghidrasql
  +-- LibGhidraSource --> libghidra HttpClient --> LibGhidraHost (protobuf RPC)
  |                                                       |
  +-- QueryEngine --> SQLite virtual tables (via libxsql)  |
                                                    Ghidra JVM
```

## Request/response notes

- `POST /query` accepts **raw SQL** in the request body, or a JSON object
  `{"sql": "...", "continue_on_error": true, "include_sql": true}`. With
  `Content-Type: application/json` the body must be valid JSON with a string
  `sql` (a malformed or `sql`-less declared-JSON body returns `400`); a body sent
  without that content type is treated as raw SQL.

## Known Limitations

- For decompiler-backed locals, treat `local_id` as an opaque canonical identifier from the source;
  do not assume it will look like `local_8` or `param_1`.

### Embedding

For the normal live-client case, `<ghidrasql/ghidrasql.hpp>` is enough:

```cpp
#include <ghidrasql/ghidrasql.hpp>

auto engine = ghidrasql::create_libghidra_engine("http://127.0.0.1:18080");
if (!engine) {
    throw std::runtime_error("failed to connect libghidra source");
}

auto result = engine->query("SELECT name FROM funcs LIMIT 5");
```

`<ghidrasql/source.hpp>` is only needed for advanced custom-source embedding:

```cpp
#include <ghidrasql/ghidrasql.hpp>
#include <ghidrasql/source.hpp>

ghidrasql::SourceCallbacks cbs;
cbs.read_functions = [&](std::vector<ghidrasql::model::FunctionRow>& out) {
    out = get_functions();
    return true;
};
auto source = ghidrasql::create_callback_live_source(std::move(cbs));
ghidrasql::QueryEngine engine(source);
auto result = engine.query("SELECT name FROM funcs LIMIT 5");
```

The public C++ surface is intentionally small:
- `<ghidrasql/ghidrasql.hpp>` for normal engine usage
- `<ghidrasql/source.hpp>` only when you are defining a custom source

### CMake options

| Option | Default | Description |
|--------|---------|-------------|
| `GHIDRASQL_WITH_LIBGHIDRA` | ON | Build with libghidra C++ client |
| `GHIDRASQL_STATIC_MSVC_RUNTIME` | `ON` on MSVC | Use the static MSVC runtime so `ghidrasql.exe` does not depend on `MSVCP140.dll` / `VCRUNTIME140.dll` |
| `GHIDRASQL_LIBGHIDRA_DIR` | (auto) | Path to a `libghidra/cpp/` source tree or a `libghidra` install prefix/package directory |

On Windows with MSVC, `ghidrasql` defaults to the static runtime so the build
stays consistent with protobuf across single-config and multi-config generators.
Pass `-DGHIDRASQL_STATIC_MSVC_RUNTIME=OFF` or set
`-DCMAKE_MSVC_RUNTIME_LIBRARY=...` explicitly if you want the DLL runtime
instead.

## Troubleshooting

- **"libghidra source unavailable"** -- rebuild with `GHIDRASQL_WITH_LIBGHIDRA=ON` (default)
- **"failed to locate LibGhidraHeadlessServer.java"** -- `LibGhidraHost` is not installed; run `gradle installExtension` from `libghidra/ghidra-extension/`
- **Stale lock files** -- if Ghidra didn't shut down cleanly, delete `*.lock` and `*.lock~` files from the project directory (kill any lingering `java.exe` first)
- **Headless host never ready** -- check that port 18080 isn't in use by another process
- **Port collision in headless+serve** -- the internal API port (18080) must differ from the ghidrasql HTTP port (default 8081); use `--port` to adjust

## The xsql family

ghidrasql is part of a family of tools that expose different binary-analysis and
debug-information platforms through the **same** SQL surface, all built on the
shared [libxsql](https://github.com/0xeb/libxsql) virtual-table framework. A
query you learn against one tool largely carries over to the others.

**Reverse-engineering platforms**
- **[idasql](https://github.com/allthingsida/idasql)** — IDA Pro databases as SQL.
- **[bnsql](https://github.com/0xeb/bnsql)** — Binary Ninja databases as SQL.

**Debug info & compiler data**
- **[pdbsql](https://github.com/0xeb/pdbsql)** — Windows PDB symbol files as SQL.
- **[dwarfsql](https://github.com/0xeb/dwarfsql)** — DWARF debug information as SQL.
- **[clangsql](https://github.com/0xeb/clangsql)** — Clang AST as SQL.

**Core**
- **[libxsql](https://github.com/0xeb/libxsql)** — the C++ SQLite virtual-table
  framework every tool above is built on.

## License and Terms of Use

In short: you may read, build, evaluate, benchmark, package, and use unmodified ghidrasql, including commercially, if you preserve notices and follow the license terms. You may fork or patch it to prepare bug fixes, optimizations, features, tests, or documentation improvements for contribution back within the license's contribution-purpose rules.

You may not maintain a divergent private fork, port, rebrand, clone, API-compatible replacement, competing implementation, or use ghidrasql as AI input to recreate or improve a derivative implementation without prior written permission from Elias Bachaalany. Independent implementations that are not copied from, materially derived from, or substantially informed by ghidrasql in the license's defined sense are not prohibited.

Permission requests: open a GitHub issue at [0xeb/ghidrasql/issues](https://github.com/0xeb/ghidrasql/issues).

If ghidrasql materially informs a distributed project, preserve the human origin: credit ghidrasql and Elias Bachaalany visibly in your README/docs and in About/credits UI when applicable. The license includes an examples/FAQ section for common allowed and permission-required uses. Third-party dependencies (libxsql, libghidra, and their transitive dependencies) remain under their own licenses.

See the full [Human-Origin Source License v1.0](LICENSE).

Releases up to v0.0.2 remain under the MPL-2.0 they shipped with.
