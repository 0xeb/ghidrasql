# ghidrasql prebuilt seed — start here

Zero-compile reverse engineering with SQL. The binaries in this archive are already
built; nothing here needs CMake, Gradle, or a compiler.

## Four commands

```bash
./scripts/verify-seed.sh                 # contents match SHA256SUMS
./scripts/bootstrap-runtime.sh           # one-time: fetch + verify Ghidra and the JDK
./scripts/run-headless.sh /bin/ls        # import, analyze, serve SQL on :8081
./scripts/query.sh 'SELECT COUNT(*) AS n FROM funcs;'
```

Stop with `./scripts/shutdown.sh`. Confirm the whole flow at once with
`./scripts/self-test.sh`.

## What is prebuilt, what is fetched

| | |
|---|---|
| **Prebuilt here** | `bin/ghidrasql` (Linux x86-64), the `LibGhidraHost` Ghidra extension, `ghidrasql-skills`, the agent prompt |
| **Fetched once by the bootstrap** | Ghidra and a Temurin JDK — pinned versions, SHA-256 verified before use |

Exact versions, commits and digests are in `PROVENANCE.md`.

## Querying

```bash
./scripts/query.sh "SELECT name, printf('0x%X', addr) AS addr FROM funcs ORDER BY size DESC LIMIT 10;"
./scripts/query.sh "SELECT * FROM binary;"
```

Run several analyses at once by passing explicit project and port arguments:

```bash
./scripts/run-headless.sh /bin/ls "$PWD/var/projects/ls" ls 8082
./scripts/query.sh 'SELECT COUNT(*) FROM funcs;' 8082
./scripts/shutdown.sh 8082
```

## Things that will bite you

- **Filter decompiler tables by `func_addr`.** `pseudocode`, `decomp_lvars` and
  `decomp_tokens` decompile on demand; an unbounded query decompiles the entire binary
  and can hang the server.
- **`shutdown` returns before the host has finished.** It answers in ~150 ms while
  Ghidra is still flushing the project. `shutdown.sh` already waits for the process —
  do not reuse a project directory until it returns.
- **`GHIDRA_INSTALL_DIR` makes `--url` fail.** If it is set, the CLI fills in `--ghidra`
  and then rejects `--url` as mutually exclusive. Use `env -u GHIDRA_INSTALL_DIR` when
  attaching to an already-running host.
- **Project paths must be absolute** with no element starting with `.`; the scripts
  resolve this for you.

## Next

- `prompts/ghidrasql_agent.md` — the full SQL surface: tables, views, functions, writes.
- `ghidrasql-skills/` — task-oriented analysis workflows.
- `chatgpt-work-install-prompt.md` — the runbook to hand to an agent.
