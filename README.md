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
- CMake 3.20+
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
  -q "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 10"
```

This imports the binary, runs full Ghidra analysis, executes your query, saves the project, and shuts down. First run takes a few minutes (analysis); subsequent runs with the same `--project` reuse the existing analysis.

## Quick Start Examples

```bash
# One-shot query (headless: import, analyze, query, shutdown)
ghidrasql --ghidra /path/to/ghidra_dist \
  --binary target.exe --project ./proj --project-name demo \
  -q "SELECT name, address FROM funcs LIMIT 10"

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
  --serve --port 8081

# Then query it: curl -X POST http://localhost:8081/query -d "SELECT * FROM funcs LIMIT 5"
```

## Example Queries

```sql
-- Functions sorted by size
SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 20;

-- Cross-references to an address
SELECT * FROM xrefs WHERE to_ea = 0x401000;

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
SELECT * FROM memory_hexdump WHERE address >= 0x401000 LIMIT 16;

-- Rename a function (write-through to Ghidra)
UPDATE funcs SET name = 'my_main' WHERE address = 0x401000;

-- Rewrite a function signature
UPDATE funcs SET signature = 'int main(int argc, char** argv)' WHERE address = 0x401000;

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
| `--serve` | Start HTTP API server |

### Program/project

| Flag | Description |
|------|-------------|
| `--binary <path>` | Binary to import (headless only) |
| `--program <name>` | Existing program in project |
| `--project <dir>` | Project directory |
| `--project-name <name>` | Project name |
| `--analyze` | Run analysis (default in headless) |
| `--no-analyze` | Skip analysis |
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
| `--max-runtime <sec>` | Host lifetime bound (default: 600, 0=disable) |
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

57 tables and 77 views covering every aspect of a Ghidra program database.

### Tables

| Category | Tables |
|----------|--------|
| **Functions** | `funcs`, `function_params`, `function_locals`, `function_frames`, `function_chunks`, `function_metrics`, `stack_vars`, `register_vars`, `tail_calls` |
| **Code** | `instructions`, `blocks`, `cfg_edges`, `loops`, `switch_tables`, `dominators`, `post_dominators` |
| **References** | `xrefs`, `call_edges`, `function_calls`, `xref_index` |
| **Symbols** | `names`, `imports`, `exports`, `strings`, `equates`, `constants` |
| **Memory** | `segments`, `memory_blocks`, `memory_bytes` |
| **Types** | `types`, `type_members`, `type_enums`, `type_enum_members`, `type_unions`, `type_aliases`, `signatures` |
| **Decompiler** | `pseudocode`, `decomp_lvars`, `decomp_tokens`, `decomp_comments` |
| **Comments** | `comments` |
| **Data** | `data_items`, `relocations` |
| **Search** | `text_index`, `search_index` |
| **Program** | `program_options`, `analysis_passes`, `transactions`, `project_properties`, `breakpoints` |
| **Meta** | `sql_capabilities`, `parity_findings`, `perf_benchmarks`, `live_meta`, `db_info` |

### Selected Views

| Category | Views |
|----------|-------|
| **Functions** | `functions`, `function_signatures`, `function_metrics_ranked`, `function_metrics_scored` |
| **Call graph** | `callgraph_edges`, `callers`, `callees`, `function_call_stats` |
| **References** | `string_refs`, `string_hotspots`, `xref_paths` |
| **Memory** | `memory_hexdump`, `memory_layout` |
| **Types** | `types_v_structs`, `types_v_unions`, `types_v_enums`, `types_v_typedefs`, `type_layout` |
| **Decompiler** | `decompiler_listing`, `ctree`, `ctree_v_calls`, `ctree_v_loops`, `ctree_v_ifs` |

Use `.tables` in the REPL to see the full list, or `SELECT name FROM sqlite_master ORDER BY name`.

### Write Operations

Write-through mutations are supported:

```sql
UPDATE funcs SET name = 'new_name' WHERE address = 0x401000;
UPDATE comments SET comment = 'note' WHERE address = 0x401000;
DELETE FROM comments WHERE address = 0x401000;
UPDATE signatures SET prototype = 'int foo(int a, int b)' WHERE entry_point = 0x401000;
UPDATE data_items SET data_type = 'int' WHERE address = 0x402000;
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

## Known Limitations

- `POST /query` expects raw SQL in the request body, not JSON.
- For decompiler-backed locals, treat `local_id` as an opaque canonical identifier from the source;
  do not assume it will look like `local_8` or `param_1`.
- The main alpha release gate is the headless private suite plus manual live-host smoke, not the older
  external-host fixture workflow tests.

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

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE).
