# GhidraSQL Agent Guide

A comprehensive reference for AI agents to effectively use GhidraSQL — an SQL interface for reverse engineering binary analysis with Ghidra.

---

## What is Ghidra and Why SQL?

**Ghidra** is the NSA's open-source reverse engineering platform. It analyzes compiled binaries (executables, DLLs, firmware) and produces:
- **Disassembly** — decoded machine instructions
- **Decompilation** — C-like pseudocode from machine code
- **Functions** — detected code boundaries with names and signatures
- **Cross-references** — who calls what, who references what data
- **Types** — structures, enums, unions, typedefs, function prototypes
- **Strings** — detected string literals

**GhidraSQL** exposes all this analysis data through SQL virtual tables, enabling:
- Complex queries across multiple data types (JOINs)
- Aggregations and statistics (COUNT, GROUP BY)
- Pattern detection across the entire binary
- **Write operations** — rename functions, retype variables, add comments, define types
- Scriptable analysis without writing Ghidra plugins or Java scripts

**Project scope:** a Ghidra project may contain many programs, but GhidraSQL's
analysis tables (`funcs`, `instructions`, `pseudocode`, etc.) always refer to
one active program. Use `project_programs` or `--list-project-programs` to
enumerate project contents, then choose the active domain path with `--program
/folder/name`.

**Input file selection (`--binary` vs `--program`):**

- **`--binary <path>`** ingests a **raw binary** (`.exe`/`.dll`/firmware/etc.)
  via Ghidra's headless importer. Use this for **fresh imports**. The
  resulting program lands in the working project; analysis is triggered
  automatically unless `--no-analyze` is passed. Repeatable for multi-binary
  projects. No need to pre-build the project — `ghidrasql --binary raw.exe
  --project ./proj --project-name demo ...` creates and populates the project
  in one shot. Imports **skip loading external system libraries by default**
  (fast) — imports-by-name still resolve, but imports-by-ordinal show as
  ordinals; pass **`--load-libraries`** to load/link them (slower, pulls
  kernel32/CRT into the project).
- **`--program <name>`** opens an **already-imported program** inside an
  existing project. Use this when you've previously imported a binary and
  want to re-attach without re-running analysis. Pair with `--no-analyze`
  for fast reopens.

Pick `--binary` for new analysis; pick `--program` to revisit existing work.

---

## CRITICAL: Performance Rules

**ALWAYS follow these rules to avoid slow queries:**

1. **`pseudocode`, `decomp_lvars`, and `decomp_tokens` MUST be function-scoped** — use `func_addr` for decompiler-backed tables. `pseudocode` and `decomp_lvars` also support exact `func_name = ...`. Unbounded queries decompile EVERY function and will hang or timeout.

2. **`instructions` MUST be scoped** — filter by `addr` range or by `func_addr` (both push down); never scan the whole instruction table.

3. **Use CTEs for xref aggregation, not correlated subqueries:**
   ```sql
   -- GOOD: Single pass over xrefs, then hash join (O(n+m))
   WITH counts AS (SELECT to_addr, COUNT(*) as n FROM xrefs WHERE is_code=1 GROUP BY to_addr)
   SELECT f.name, COALESCE(c.n, 0) FROM funcs f LEFT JOIN counts c ON c.to_addr = f.addr;

   -- BAD: Executes subquery for EACH function (O(n*m))
   SELECT name, (SELECT COUNT(*) FROM xrefs WHERE to_addr = funcs.addr) FROM funcs;
   ```

4. **Use `callgraph_edges`, `callers`, `callees` views** for call graph analysis — they pre-compute function names via JOINs.

5. **Use `string_refs` view** for string cross-reference analysis — it joins strings, xrefs, and funcs efficiently.

6. **Join `funcs` only in the final SELECT** — not in every CTE step.

7. **Prefer `xref_index` when you need function attribution for raw xrefs** — it precomputes `src_func_addr` and `dst_func_addr`, avoiding repeated range joins on `funcs`.

9. **For recursive/path queries, bound depth and track visited nodes** — use `callgraph_edges`, `callers`, or `callees` as the edge source and keep recursion target-specific.

---

## Few-Shot Examples (Use These Patterns!)

### "Find the largest functions"
```sql
SELECT name, printf('0x%X', addr) as addr, size
FROM funcs
ORDER BY size DESC
LIMIT 10;
```

### "Find the most called functions"
```sql
WITH caller_counts AS (
    SELECT to_addr, COUNT(*) as callers
    FROM xrefs WHERE is_code = 1
    GROUP BY to_addr
)
SELECT f.name, printf('0x%X', f.addr) as addr, c.callers
FROM funcs f
JOIN caller_counts c ON f.addr = c.to_addr
ORDER BY c.callers DESC
LIMIT 10;
```

### "Find orphan functions (no callers)"
```sql
WITH has_callers AS (
    SELECT DISTINCT to_addr FROM xrefs WHERE is_code = 1
)
SELECT f.name, printf('0x%X', f.addr) as addr
FROM funcs f
WHERE f.addr NOT IN (SELECT to_addr FROM has_callers)
ORDER BY f.name;
```

### "Find functions calling malloc"
```sql
SELECT DISTINCT ce.src_func_name, printf('0x%X', ce.src_func_addr) as addr
FROM callgraph_edges ce
WHERE ce.dst_func_name LIKE '%malloc%';
```

### "Who calls A recursively?"
```sql
WITH RECURSIVE callers_cte(func_addr, depth, path) AS (
    SELECT caller_func_addr, 1, printf('%lld', caller_func_addr)
    FROM callers
    WHERE func_addr = 0x401060

    UNION ALL

    SELECT c.caller_func_addr, callers_cte.depth + 1,
           callers_cte.path || '>' || printf('%lld', c.caller_func_addr)
    FROM callers c
    JOIN callers_cte ON c.func_addr = callers_cte.func_addr
    WHERE callers_cte.depth < 5
      AND instr(callers_cte.path, printf('%lld', c.caller_func_addr)) = 0
)
SELECT func_at(func_addr) AS caller, MIN(depth) AS distance
FROM callers_cte
GROUP BY func_addr
ORDER BY distance, caller;
```

### "Find a path between A and B"
```sql
WITH RECURSIVE path(root_func, current_func, depth, path) AS (
    SELECT src_func_addr, dst_func_addr, 1,
           printf('%lld>%lld', src_func_addr, dst_func_addr)
    FROM callgraph_edges
    WHERE src_func_addr = 0x401030

    UNION ALL

    SELECT path.root_func, c.dst_func_addr, path.depth + 1,
           path.path || '>' || printf('%lld', c.dst_func_addr)
    FROM path
    JOIN callgraph_edges c ON c.src_func_addr = path.current_func
    WHERE path.depth < 6
      AND instr(path.path, printf('%lld', c.dst_func_addr)) = 0
)
SELECT printf('0x%X', current_func) AS node, depth, path
FROM path
WHERE current_func = 0x401060
ORDER BY depth;
```

### "Explore the xref neighborhood around a function"
```sql
SELECT printf('0x%X', from_addr) AS from_addr,
       printf('0x%X', to_addr) AS to_addr,
       kind
FROM xref_index
WHERE src_func_addr = 0x401030 OR dst_func_addr = 0x401030
ORDER BY from_addr, to_addr;
```

### "Find strings containing 'password'"
```sql
SELECT printf('0x%X', addr) as addr, content
FROM strings
WHERE content LIKE '%password%';
```

### "Which functions reference a specific string?"
```sql
SELECT func_name, printf('0x%X', func_addr) as func_addr, string_value
FROM string_refs
WHERE string_value LIKE '%error%' OR string_value LIKE '%fail%';
```

### "Decompile a function and show its variables"
```sql
-- Get pseudocode
SELECT text FROM pseudocode WHERE func_addr = 0x4011F0;

-- Get local variables
SELECT local_id, name, type, storage FROM decomp_lvars WHERE func_addr = 0x4011F0;

-- Inspect individual tokens with semantic info
SELECT text, kind, var_name, var_type FROM decomp_tokens WHERE func_addr = 0x4011F0;
```

### "Annotate a function" (the critical workflow)
```sql
-- 1. Rename the function
UPDATE funcs SET name = 'parseConfig' WHERE addr = 0x4011F0;

-- 2. Set function signature
UPDATE funcs SET prototype = 'int parseConfig(const char* path, Config* out)' WHERE addr = 0x4011F0;

-- 3. Query the canonical local_id first, then rename that exact row
-- Example local_id values are source-defined and may look like arg0 or local:stack[-0x8]:4
UPDATE decomp_lvars SET name = 'configPath' WHERE func_addr = 0x4011F0 AND local_id = '<local_id_from_query>';

-- 4. Set a variable's type
UPDATE decomp_lvars SET type = 'char *' WHERE func_addr = 0x4011F0 AND local_id = '<local_id_from_query>';

-- 5. Rename a parameter
UPDATE function_params SET param_name = 'path' WHERE func_addr = 0x4011F0 AND ordinal = 0;

-- 6. Add a comment
INSERT INTO comments (addr, comment, source) VALUES (0x4011F0, 'Parses config file', 'eol');

-- 7. Re-decompile to see changes
SELECT text FROM pseudocode WHERE func_addr = 0x4011F0;

-- 8. Save to Ghidra project
SELECT save_database();
```

### "Import types and apply them"
```sql
-- 1. Import custom types via C declarations
SELECT parse_decls('typedef enum { CMD_INIT=0, CMD_RUN=1, CMD_STOP=2 } CmdType;
typedef struct { CmdType type; int flags; char name[32]; } Command;
typedef struct { int status; int error; char msg[64]; } Result;');

-- 2. Apply the types to a function signature
UPDATE funcs SET prototype = 'int processCommand(Command * cmd, Result * out)'
WHERE name = 'FUN_00401200';

-- 3. Re-decompile to see typed output
SELECT text FROM pseudocode WHERE func_addr = 0x401200;

-- 4. Save
SELECT save_database();
```

### "Tag functions by category"
```sql
-- 1. Create semantic tags
INSERT INTO function_tags (name, comment) VALUES ('crypto', 'Cryptographic operations');
INSERT INTO function_tags (name, comment) VALUES ('network', 'Network I/O functions');
INSERT INTO function_tags (name, comment) VALUES ('parsing', 'Input parsing and validation');

-- 2. Tag functions based on imports they call
INSERT INTO function_tag_mappings (func_addr, tag_name)
SELECT DISTINCT ce.src_func_addr, 'crypto'
FROM callgraph_edges ce
WHERE ce.dst_func_name LIKE '%Crypt%' OR ce.dst_func_name LIKE '%Hash%'
   OR ce.dst_func_name LIKE '%AES%' OR ce.dst_func_name LIKE '%SHA%';

INSERT INTO function_tag_mappings (func_addr, tag_name)
SELECT DISTINCT ce.src_func_addr, 'network'
FROM callgraph_edges ce
WHERE ce.dst_func_name LIKE '%socket%' OR ce.dst_func_name LIKE '%connect%'
   OR ce.dst_func_name LIKE '%send%' OR ce.dst_func_name LIKE '%recv%'
   OR ce.dst_func_name LIKE '%WSA%';

-- 3. Review tagged functions
SELECT f.name, printf('0x%X', f.addr) as addr, m.tag_name
FROM function_tag_mappings m
JOIN funcs f ON f.addr = m.func_addr
ORDER BY m.tag_name, f.name;

-- 4. Find functions with multiple tags (bridge functions)
SELECT f.name, GROUP_CONCAT(m.tag_name, ', ') as tags, COUNT(*) as tag_count
FROM function_tag_mappings m
JOIN funcs f ON f.addr = m.func_addr
GROUP BY m.func_addr
HAVING tag_count > 1;

-- 5. Save
SELECT save_database();
```

### "What does this binary do?"
```sql
-- Program metadata
SELECT * FROM binary;

-- Entry points
SELECT name, printf('0x%X', addr) as addr FROM entries;

-- Imported APIs (hints at functionality)
SELECT module, name FROM imports ORDER BY module, name;

-- Interesting strings
SELECT content FROM strings WHERE length > 10 ORDER BY length DESC LIMIT 20;
```

---

## Core Concepts for Binary Analysis

### Addresses
Everything in a binary has an **address** — a memory location where code or data lives. SQL shows these as integers; use `printf('0x%X', addr)` or `hex(addr)` for hex display.

### Functions
Ghidra groups code into **functions** with:
- `addr` — where the function begins
- `name` — assigned or auto-generated name (e.g., `main`, `FUN_004011f0`)
- `size` — total bytes in the function
- `prototype` — full prototype (e.g., `int main(int argc, char** argv)`)

### Cross-References (xrefs)
Binary analysis is about understanding **relationships**:
- **Code xrefs** (`is_code = 1`) — function calls, jumps between code
- **Data xrefs** (`is_data = 1`) — code reading/writing data locations
- `from_addr` -> `to_addr` represents "address X references address Y"

### Segments
Memory is divided into **segments** with different purposes:
- `.text` — executable code
- `.data` — initialized global data
- `.rdata` / `.rodata` — read-only data (strings, constants)
- `.bss` — uninitialized data

### Basic Blocks
Within a function, **basic blocks** are straight-line code sequences with no branches in the middle. Useful for control flow analysis via the `blocks` and `cfg_edges` tables.

---

## Tables Reference

### funcs
All detected functions in the binary.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Function start address |
| `name` | TEXT | UPDATE | Function name |
| `size` | INT64 | | Function size in bytes |
| `end_addr` | INT64 | | Function end address (addr + size) |
| `flags` | INT64 | | Function flags |
| `namespace` | TEXT | | Namespace name |
| `prototype` | TEXT | UPDATE | Function prototype |
| `return_type` | TEXT | | Parsed return type from signature |
| `arg_count` | INT64 | | Number of parameters |
| `calling_conv` | TEXT | | Calling convention |
| `return_is_ptr` | INT | | Return type is pointer (0/1) |
| `return_is_void` | INT | | Return type is void (0/1) |
| `return_is_int` | INT | | Return type is int (0/1) |
| `return_is_integral` | INT | | Return type is integral (0/1) |

```sql
-- 10 largest functions
SELECT name, printf('0x%X', addr) as addr, size FROM funcs ORDER BY size DESC LIMIT 10;

-- Rename a function
UPDATE funcs SET name = 'main' WHERE addr = 0x401000;

-- Set function signature
UPDATE funcs SET prototype = 'int main(int argc, char** argv)' WHERE addr = 0x401000;
```

### strings
String literals found in the binary.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | String address |
| `length` | INT64 | | String length |
| `type` | TEXT | | String type identifier |
| `type_name` | TEXT | | Normalized type (ascii/utf16/utf32) |
| `width` | INT | | Character width (1/2/4) |
| `width_name` | TEXT | | Width description |
| `layout` | INT | | Layout type |
| `layout_name` | TEXT | | Layout description |
| `encoding` | TEXT | | Encoding name |
| `content` | TEXT | | **The string content** |

```sql
-- Find error messages
SELECT content, printf('0x%X', addr) as addr FROM strings WHERE content LIKE '%error%';

-- Longest strings
SELECT printf('0x%X', addr) as addr, length, content FROM strings ORDER BY length DESC LIMIT 20;
```

**IMPORTANT:** The string content column is `content`, NOT `value`.

### xrefs
Cross-references between addresses.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `from_addr` | INT64 | | Source address (who references) |
| `to_addr` | INT64 | | Target address (what is referenced) |
| `kind` | TEXT | | Reference type |
| `is_code` | INT | | 1=code xref (call/jump) |
| `is_data` | INT | | 1=data xref |

```sql
-- Who calls function at 0x401000?
SELECT printf('0x%X', from_addr) as caller FROM xrefs WHERE to_addr = 0x401000 AND is_code = 1;
```

**NOTE:** Unlike bnsql, ghidrasql's xrefs table does NOT have a pre-computed `from_func` column. Use the `callers`, `callees`, or `callgraph_edges` views for call graph analysis.

### call_edges
Raw call graph edges with addresses.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `src_func_addr` | INT64 | | Caller function address |
| `call_site` | INT64 | | Call instruction address |
| `dst_addr` | INT64 | | Call target address |
| `dst_func_addr` | INT64 | | Callee function address |
| `kind` | TEXT | | Call type |

### blocks
Basic blocks within functions.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `func_addr` | INT64 | | Containing function |
| `start_addr` | INT64 | | Block start address |
| `end_addr` | INT64 | | Block end address |
| `in_degree` | INT | | Incoming edges |
| `out_degree` | INT | | Outgoing edges |

### cfg_edges
Control flow graph edges within functions.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `func_addr` | INT64 | | Containing function |
| `from_addr` | INT64 | | Source block start |
| `to_addr` | INT64 | | Destination block start |
| `edge_type` | TEXT | | Edge kind (fall-through, branch, etc.) |

### instructions
Decoded instructions. Filter by `addr` range **or** by `func_addr` (both push down).

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Instruction address |
| `mnemonic` | TEXT | | Instruction mnemonic |
| `operands` | TEXT | | Operand string |
| `disasm` | TEXT | | Full disassembly line |
| `size` | INT | | Instruction size in bytes |
| `bytes` | TEXT | | Hex byte string |
| `func_addr` | INT64 | | Start address of the containing function (0 if outside any function); indexed and pushed down |

```sql
-- Instruction profile of an address range (use funcs to get start/end)
SELECT mnemonic, COUNT(*) as count
FROM instructions WHERE addr BETWEEN 0x401000 AND 0x401100
GROUP BY mnemonic ORDER BY count DESC;

-- All instructions in one function (func_addr filter pushes down)
SELECT printf('0x%X', addr) AS addr, mnemonic, operands
FROM instructions WHERE func_addr = 0x401000 ORDER BY addr;
```

### instruction_operands
One row per decoded instruction operand (Ghidra `getDefaultOperandRepresentation` /
`getOperandType` / `getOperandRefType`). Filter by `addr` (one instruction) **or**
`func_addr` (both push down).

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Instruction address |
| `func_addr` | INT64 | | Containing function (0 if outside any function) |
| `operand_index` | INT | | 0-based operand position |
| `text` | TEXT | | Rendered operand (`RAX`, `0x10`, `[RBP + -0x4]`) |
| `type_name` | TEXT | | `register` / `immediate` / `memory` / `address` / … |
| `ref_type` | TEXT | | Ghidra RefType (`READ`, `WRITE`, `READ_WRITE`, `DATA`, …) |

```sql
-- operands of one instruction
SELECT operand_index, text, type_name, ref_type
FROM instruction_operands WHERE addr = 0x401000 ORDER BY operand_index;
```

### pseudocode
Decompiled C-like pseudocode. **MUST be function-scoped by `func_addr` or exact `func_name = ...`.**

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `func_addr` | INT64 | | Function address |
| `func_name` | TEXT | | Function name |
| `text` | TEXT | | **Full pseudocode text** |
| `is_stale` | INT | | Stale flag |

```sql
-- Decompile a specific function
SELECT text FROM pseudocode WHERE func_addr = 0x401000;
SELECT func_addr, text FROM pseudocode WHERE func_name = 'main';
```

**IMPORTANT:** The `text` column contains the entire function's decompilation as a single string. This is different from bnsql where pseudocode has per-line rows with `line` and `line_num` columns.

### decomp_lvars
Decompiler local variables. **MUST be function-scoped; use `func_addr`, or exact `func_name = ...` for reads.** Used for renaming and retyping variables.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `func_addr` | INT64 | | Function address |
| `func_name` | TEXT | | Function name |
| `local_id` | TEXT | | Stable source-defined local identifier; query it first and use it verbatim for writes |
| `name` | TEXT | UPDATE | Variable name |
| `type` | TEXT | UPDATE | Variable type |
| `storage` | TEXT | | Storage location |
| `role` | TEXT | | Variable role (param, local, etc.) |

```sql
-- List variables in a function
SELECT local_id, name, type, storage FROM decomp_lvars WHERE func_addr = 0x401000;
SELECT func_addr, local_id, name, type, storage FROM decomp_lvars WHERE func_name = 'main';

-- Rename a variable (paste the exact local_id returned above)
UPDATE decomp_lvars SET name = 'buffer' WHERE func_addr = 0x401000 AND local_id = '<local_id_from_query>';

-- Set variable type
UPDATE decomp_lvars SET type = 'char *' WHERE func_addr = 0x401000 AND local_id = '<local_id_from_query>';
```

**IMPORTANT:** This table is called `decomp_lvars`, NOT `hlil_vars` (that's bnsql).

### decomp_tokens
Structured decompiler tokens with semantic information from Ghidra's ClangToken data. **MUST filter by `func_addr`.**

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `func_addr` | INT64 | | Function entry point |
| `token_index` | INT64 | | Sequential ID within function |
| `text` | TEXT | | Token text |
| `kind` | TEXT | | Token kind: keyword/variable/type/function/parameter/global/const/comment/default/error/special |
| `line` | INT64 | | 1-based line number |
| `column` | INT64 | | Position within line |
| `var_name` | TEXT | | Variable name (NULL for non-variable tokens) |
| `var_type` | TEXT | | Variable data type (NULL for non-variable tokens) |
| `var_storage` | TEXT | | Storage: stack/register/memory (NULL for non-variable tokens) |

```sql
-- Inspect decompiler tokens for a function
SELECT text, kind, var_name, var_type FROM decomp_tokens WHERE func_addr = 0x401000;

-- Find all variable references in a function
SELECT text, kind, var_name, var_type, var_storage
FROM decomp_tokens
WHERE func_addr = 0x401000 AND kind = 'variable';

-- Reconstruct pseudocode from tokens
SELECT text FROM decomp_tokens WHERE func_addr = 0x401000 ORDER BY token_index;
```

### pcode_ops
Ghidra's **P-code** op stream per function — the real register-transfer IR below the
token/AST layer, and the Ghidra leg of the cross-tool low-IR. Each row is one `PcodeOp`
in intra-function order, served by the DecompilerService/GetPcode RPC. By default the
**high** (refined SSA) rung; add `AND maturity='raw'` for **raw** per-instruction,
non-SSA P-code (~3.5× more ops, no MULTIEQUAL/INDIRECT/CAST/PTRADD — machine-level).
**Filter by `func_addr`** (one `GetPcode` RPC per function; an unfiltered scan
decompiles every function once). Read-only.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `func_addr` | INT64 | | Containing function address |
| `seq` | INT64 | | Intra-function order |
| `addr` | INT64 | | Source machine address (NULL only when absent; a real address 0 stays 0) |
| `op` | TEXT | | Canonical P-code mnemonic (`COPY`, `LOAD`, `STORE`, `INT_ADD`, `INT_SUB`, `CALL`, `RETURN`, `MULTIEQUAL`, ...) |
| `has_output` | INT | | 1 if the op defines a varnode |
| `output_kind` | TEXT | | Canonical operand kind (`reg`/`imm`/`mem`/`result`/`var`); NULL when the op has no output |
| `output_size` | INT | | Output size in bytes |
| `input_count` | INT | | Input varnode arity |
| `is_ssa` | INT | | 1 for high (SSA), 0 for raw |
| `maturity` | TEXT | | Returned rung: `high` \| `raw` (passthrough filter) |
| `stage` | TEXT | | Coarse ordinal: `ssa` (high) \| `raw` (passthrough filter) |

```sql
-- The high (SSA) P-code op stream of one function
SELECT seq, addr, op, has_output, output_kind, input_count
FROM pcode_ops WHERE func_addr = 0x401000 ORDER BY seq;

-- Raw (non-SSA) machine-level P-code of the same function
SELECT seq, op FROM pcode_ops WHERE func_addr = 0x401000 AND maturity = 'raw' ORDER BY seq;
```

Discover the rungs with `SELECT * FROM ir_maturities` (2 rows: `high` default, `raw`).
Unlike the `ctree*` views (SQL compositions, not a real AST), `pcode_ops` is the genuine
P-code — use it for engine-agnostic dataflow, call/mem-write detection, and cross-tool
lifter comparison over canonical `op` sequences.

### pcode_varnodes
The P-code **value operands** (varnodes) — one row per op output + each input, projected
onto the 5-kind model. Join `pcode_ops` on `op_seq = seq`. Columns: `func_addr`, `op_seq`,
`operand_index`, `role` (`out` = op output, `in` = op input), `kind`
(`reg`/`imm`/`mem`/`result`/`var`), `space` (address space), `offset`, `size`, `maturity`,
`stage`. Same `func_addr`/`maturity` pushdown. The unified **`ir_operands`** view projects
this. Read-only.

### function_params
Function parameters. Used for renaming and retyping parameters.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `func_addr` | INT64 | | Function address |
| `ordinal` | INT64 | | Parameter ordinal (0-based) |
| `param_name` | TEXT | UPDATE | Parameter name |
| `param_type` | TEXT | UPDATE | Parameter type |
| `storage` | TEXT | | Storage location |
| `is_user_named` | INT | | User-named flag |

```sql
-- Rename first parameter
UPDATE function_params SET param_name = 'argc' WHERE func_addr = 0x401000 AND ordinal = 0;

-- Set parameter type
UPDATE function_params SET param_type = 'int' WHERE func_addr = 0x401000 AND ordinal = 0;
```

### comments
Address comments / annotations.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Comment address |
| `comment` | TEXT | UPDATE | Comment text |
| `repeatable` | INT | UPDATE | Repeatable flag (0/1) |
| `source` | TEXT | UPDATE | Comment source/kind (eol, pre, post, plate) |

**Write support:** UPDATE comment, UPDATE repeatable, INSERT, DELETE

```sql
-- Add an EOL comment
INSERT INTO comments (addr, comment, source) VALUES (0x401000, 'entry point', 'eol');

-- Add a plate (function header) comment
INSERT INTO comments (addr, comment, source) VALUES (0x401000, 'Main entry', 'plate');

-- Update existing comment
UPDATE comments SET comment = 'new text' WHERE addr = 0x401000 AND source = 'eol';

-- Delete a comment
DELETE FROM comments WHERE addr = 0x401000 AND source = 'eol';
```

### names
All named locations (symbols).

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Symbol address |
| `name` | TEXT | UPDATE | Symbol name |
| `symbol_kind` | TEXT | | Symbol type/kind |
| `namespace` | TEXT | | Namespace name |
| `is_primary` | INT | | Primary symbol flag |
| `is_external` | INT | | External symbol flag |

**Write support:** UPDATE name, INSERT, DELETE

```sql
-- Create a new symbol
INSERT INTO names (addr, name) VALUES (0x401000, 'myLabel');

-- Delete a symbol
DELETE FROM names WHERE addr = 0x401000;
```

### imports
Imported functions from external libraries.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Import address |
| `name` | TEXT | | Import name |
| `module` | TEXT | | Source module/DLL |

```sql
-- Imports by module
SELECT module, COUNT(*) as cnt FROM imports GROUP BY module ORDER BY cnt DESC;

-- Find kernel32 imports
SELECT name FROM imports WHERE module LIKE '%kernel32%';
```

### entries
Exported functions.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Export address |
| `name` | TEXT | | Export name |
| `module` | TEXT | | Module name |

### data_items
Defined data items in the binary.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Data address |
| `name` | TEXT | UPDATE | Data label |
| `data_type` | TEXT | UPDATE | Type name |
| `size` | INT64 | | Data size |
| `value_repr` | TEXT | | Value representation |
| `segment_name` | TEXT | | Containing segment |
| `is_string` | INT | | Is string data (0/1) |
| `is_initialized` | INT | | Is initialized (0/1) |

**Write support:** UPDATE name, UPDATE data_type, INSERT, DELETE

```sql
-- Define a new data item only at a verified unused, writable data address
INSERT INTO data_items (addr, data_type) VALUES (<unused_data_addr>, 'dword');

-- Rename a data item
UPDATE data_items SET name = 'g_config' WHERE addr = <data_addr>;

-- Delete a data item
DELETE FROM data_items WHERE addr = 0x403000;
```

### bytes
Every mapped byte of the program, with CoW write support. Surfaces instruction
bytes, string bytes, defined-data bytes, initialized filler, AND
uninitialized-block bytes. For an uninitialized byte, `value` is **NULL**
(`is_initialized = 0`) — this preserves the "byte is 0" vs "byte is unknown"
distinction. `WHERE is_initialized = 1` reproduces the initialized-only view.
Served by a streaming windowed generator: a point (`addr =`) or range
(`BETWEEN` / `>=` / `<=`) predicate streams only the requested window (no image
materialization); an unconstrained scan streams the whole image in bounded
memory but still visits every mapped byte — constrain by `addr` for speed.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Byte address |
| `value` | INT | UPDATE | Byte value (0-255); **NULL** when `is_initialized = 0` |
| `segment_name` | TEXT | | Containing segment |
| `func_addr` | INT64 | | Containing function |
| `source_kind` | TEXT | | `instruction` / `string` / `data` / `raw` (initialized filler) / `uninitialized` |
| `item_addr` | INT64 | | Parent item address |
| `item_offset` | INT64 | | Offset within item |
| `is_printable` | INT | | Is printable ASCII (0/1); 0 when uninitialized |
| `ascii` | TEXT | | ASCII representation; empty when uninitialized |
| `is_initialized` | INT | | 1 = mapped initialized byte (known value); 0 = mapped uninitialized (value NULL) |

Patching a byte where `is_initialized = 0` is rejected (no backing storage until
the block is initialized).

```sql
-- Patch a byte
UPDATE bytes SET value = 0x90 WHERE addr = 0x401005;

-- Initialized-only view of a range (the pre-parity behavior)
SELECT addr, value, ascii FROM bytes
WHERE addr BETWEEN 0x401000 AND 0x401100 AND is_initialized = 1;

-- Find uninitialized (.bss-style) bytes in a range
SELECT addr FROM bytes
WHERE addr BETWEEN 0x600000 AND 0x600100 AND is_initialized = 0;
```

### byte_search
Canonical cross-tool byte-pattern search (matches idasql/bnsql/r2sql). Pure
client-side: enumerates memory blocks and pages each through the existing
`read_bytes` RPC, matching a FlexHex pattern in C++ (no Java host change).
**Requires** `WHERE pattern = '<FlexHex>'` — a bare scan errors (`matched_hex` is an
output column, not the input). Optional bounds via `start_addr`/`end_addr`/
`max_results` (hidden) or an `addr` range predicate.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Match address |
| `matched_hex` | TEXT | | Matched bytes, spaced lowercase (e.g. `48 8b`) |
| `matched_bytes` | BLOB | | Matched bytes |
| `size` | INT | | Match length |
| `pattern` | TEXT | *hidden input* | FlexHex: `48 8B ?? 00`, `4?`/`?F` nibble wildcards |
| `start_addr`, `end_addr`, `max_results` | INT | *hidden inputs* | Optional bounds / cap |

```sql
-- Find a pattern, first 10 hits
SELECT printf('0x%x', addr) AS at, matched_hex FROM byte_search
WHERE pattern = '48 8B ?? 00' AND max_results = 10;

-- Bounded to a range
SELECT addr FROM byte_search
WHERE pattern = 'CC CC CC' AND start_addr = 0x401000 AND end_addr = 0x402000;
```

### segments
Memory segments / blocks. **Writable**: INSERT a region (Ghidra
createUninitializedBlock), DELETE it (removeBlock), and UPDATE `start_addr`
(rebase/moveBlock). The richer `memory_blocks` table (and `memory_layout` view)
expose the same map and are writable the same way.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `start_addr` | INT64 | UPDATE | Segment start; UPDATE rebases (moves) the block |
| `end_addr` | INT64 | | Segment end |
| `name` | TEXT | | Segment / block name |
| `class` | TEXT | | Segment class |
| `perm` | INT | INSERT | Permissions (R=4, W=2, X=1) |
| `bitness` | INT | | Architecture bitness |

```sql
-- Add an SRAM region to a firmware image's memory map, then rebase a region
INSERT INTO segments(start_addr, end_addr, name, perm)
  VALUES (0x20000000, 0x20005000, 'SRAM', 6);
UPDATE segments SET start_addr = 0x08000000 WHERE name = '.text';  -- rebase
DELETE FROM segments WHERE name = 'SRAM';
```

### types
Type definitions (structs, enums, unions, typedefs, function types).

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `type_id` | TEXT | | Type identifier |
| `name` | TEXT | UPDATE | Type name |
| `kind` | TEXT | | Type kind (struct, enum, union, typedef, function) |
| `size` | INT64 | | Type size in bytes |
| `declaration` | TEXT | | Type declaration |

**Write support:** UPDATE name, INSERT, DELETE

```sql
-- Create a new struct type
INSERT INTO types (name, kind, size) VALUES ('MyStruct', 'struct', 16);

-- Delete a type
DELETE FROM types WHERE name = 'OldStruct';
```

### type_members
Struct/union members.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `parent_type_id` | TEXT | | Parent type ID |
| `parent_type_name` | TEXT | | Parent type name |
| `member_name` | TEXT | UPDATE | Member name |
| `member_type` | TEXT | UPDATE | Member type |
| `offset` | INT64 | | Member offset |
| `size` | INT64 | | Member size |
| `ordinal` | INT64 | | Member ordinal |
| `comment` | TEXT | UPDATE | Member comment |

**Write support:** UPDATE member_name/member_type/comment, INSERT, DELETE

```sql
-- Add a member to a struct
INSERT INTO type_members (parent_type_id, member_name, member_type, size)
VALUES ('type_id_here', 'field1', 'int', 4);

-- Delete a member
DELETE FROM type_members WHERE parent_type_id = 'type_id_here' AND ordinal = 2;
```

### type_enums
Enum type definitions.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `type_id` | TEXT | | Type identifier |
| `name` | TEXT | UPDATE | Enum name |
| `width` | INT64 | | Enum width |
| `is_signed` | INT | | Signed flag |
| `declaration` | TEXT | | Enum declaration |

**Write support:** UPDATE name, INSERT, DELETE

```sql
-- Create a new enum
INSERT INTO type_enums (name, width) VALUES ('ErrorCode', 4);
```

### type_enum_members
Enum values/members.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `type_id` | TEXT | | Parent type ID |
| `name` | TEXT | UPDATE | Member name |
| `value` | INT64 | UPDATE | Member value |
| `ordinal` | INT64 | | Member ordinal |
| `comment` | TEXT | UPDATE | Member comment |

**Write support:** UPDATE name/value/comment, INSERT, DELETE

```sql
-- Add an enum value
INSERT INTO type_enum_members (type_id, name, value) VALUES ('type_id_here', 'ERR_OK', 0);
```

### type_unions
Union type definitions.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `type_id` | TEXT | | Type identifier |
| `name` | TEXT | UPDATE | Union name |
| `size` | INT64 | | Union size |
| `declaration` | TEXT | | Union declaration |

**Write support:** UPDATE name, INSERT, DELETE

### type_aliases
Typedef / type alias definitions.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `type_id` | TEXT | | Type identifier |
| `name` | TEXT | UPDATE | Alias name |
| `target_type` | TEXT | UPDATE | Target type |
| `declaration` | TEXT | | Typedef declaration |

**Write support:** UPDATE name, UPDATE target_type, INSERT, DELETE

```sql
-- Create a typedef
INSERT INTO type_aliases (name, target_type) VALUES ('DWORD', 'unsigned int');
```

### signatures
Function signatures with detailed prototype info.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `sig_id` | TEXT | | Signature identifier |
| `owner_kind` | TEXT | | Owner type |
| `owner_addr` | INT64 | | Owner address |
| `name` | TEXT | UPDATE | Signature name — writable for function rows only (renames the owning function) |
| `prototype` | TEXT | UPDATE | Full prototype string |
| `calling_convention` | TEXT | | Calling convention |
| `is_variadic` | INT | | Variadic flag |
| `return_type` | TEXT | | Return type |
| `param_count` | INT64 | | Parameter count |

**Write support:** UPDATE name (function rows only), UPDATE prototype. To change
the calling convention or return type, write a full prototype string.

### decomp_comments
Decompiler-specific comments. **Filter by `func_addr`.**

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `func_addr` | INT64 | | Function address |
| `addr` | INT64 | | Comment address |
| `comment` | TEXT | UPDATE | Comment text |
| `source` | TEXT | UPDATE | Comment source |

**Write support:** UPDATE comment, UPDATE source, INSERT, DELETE

### breakpoints
Debug breakpoints.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Breakpoint address |
| `enabled` | INT | UPDATE | Enabled flag |
| `type` | INT | UPDATE | Type (0=software, 1=hardware, 2=read_watch, 3=access_watch) |
| `type_name` | TEXT | | Type name |
| `size` | INT64 | UPDATE | Watchpoint size |
| `flags` | INT64 | | Breakpoint flags |
| `pass_count` | INT | | Pass count |
| `condition` | TEXT | UPDATE | Condition expression |
| `group` | TEXT | UPDATE | Breakpoint group |
| `loc_type` | INT | | Location type (0=address, 1=module, 2=symbol, 3=source) |
| `loc_type_name` | TEXT | | Location type name |

**Write support:** UPDATE enabled/type/size/condition/group, INSERT, DELETE

### bookmarks
Code bookmarks.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `addr` | INT64 | | Bookmark address |
| `type` | TEXT | UPDATE | Bookmark type |
| `category` | TEXT | UPDATE | Bookmark category |
| `comment` | TEXT | UPDATE | Bookmark comment |

**Write support:** UPDATE type/category/comment, INSERT, DELETE

### function_tags
Function tag definitions — Ghidra-native categorization system. Unlike bookmarks (address-based), tags are semantic labels applied to entire functions. Use these to categorize functions by purpose (crypto, networking, parsing, etc.) during analysis.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `name` | TEXT | | Tag name (unique identifier) |
| `comment` | TEXT | | Tag description |

**Write support:** INSERT, DELETE

```sql
-- Create a new tag
INSERT INTO function_tags (name, comment) VALUES ('crypto', 'Cryptographic functions');

-- Create tag without comment
INSERT INTO function_tags (name) VALUES ('network');

-- List all tags
SELECT name, comment FROM function_tags;

-- Delete a tag (also removes all function associations)
DELETE FROM function_tags WHERE name = 'crypto';
```

### function_tag_mappings
Function-to-tag associations. Each row means "this function has this tag." A function can have multiple tags, and a tag can be applied to many functions.

| Column | Type | Writable | Description |
|--------|------|----------|-------------|
| `func_addr` | INT64 | | Function entry address |
| `tag_name` | TEXT | | Tag name (references function_tags) |

**Write support:** INSERT (tag a function), DELETE (untag a function)

```sql
-- Tag a function
INSERT INTO function_tag_mappings (func_addr, tag_name) VALUES (0x140001000, 'crypto');

-- Tag multiple functions
INSERT INTO function_tag_mappings (func_addr, tag_name) VALUES (0x140001200, 'crypto');
INSERT INTO function_tag_mappings (func_addr, tag_name) VALUES (0x140001200, 'network');

-- List all tagged functions
SELECT printf('0x%X', m.func_addr) as addr, f.name, m.tag_name
FROM function_tag_mappings m
JOIN funcs f ON f.addr = m.func_addr
ORDER BY m.tag_name, f.name;

-- Find functions with a specific tag
SELECT f.name, printf('0x%X', f.addr) as addr
FROM function_tag_mappings m
JOIN funcs f ON f.addr = m.func_addr
WHERE m.tag_name = 'crypto';

-- What tags does a specific function have?
SELECT tag_name FROM function_tag_mappings WHERE func_addr = 0x140001000;

-- Remove a tag from a function
DELETE FROM function_tag_mappings WHERE func_addr = 0x140001000 AND tag_name = 'crypto';

-- Count functions per tag
SELECT tag_name, COUNT(*) as func_count
FROM function_tag_mappings
GROUP BY tag_name ORDER BY func_count DESC;
```

**NOTE:** When you INSERT into `function_tag_mappings`, the tag is auto-created if it doesn't exist yet. However, explicitly creating tags via `function_tags` with a descriptive `comment` is recommended for clarity.

### binary
Program metadata — key/value shape: `(key TEXT, value TEXT, type TEXT)`, one
row per fact, `type ∈ {string, hex, bool, int}`. The shape and canonical key
names are shared across the tool family, so the same `WHERE key = '…'` query
works on every engine. The `summary` row is first, so `SELECT * FROM binary`
shows the digest up top.

| Key | Type | Description |
|-----|------|-------------|
| `summary` | string | One-line program digest (first row) |
| `tool_name` | string | Always `ghidrasql` |
| `tool_version` | string | ghidrasql build version |
| `processor` | string | Processor from `language_id` (e.g. `x86`) |
| `filetype` | string | Executable format from the loader (e.g. `Portable Executable (PE)`); omitted when unreported |
| `image_base` | hex | Image base address |
| `entry_point` | hex | Program entry point; omitted when the loader reports none |
| `min_addr` | hex | Lowest mapped address (from the memory map); omitted when no blocks |
| `max_addr` | hex | End of the highest mapped block; omitted when no blocks |
| `is_64bit` | bool | `true`/`false`, from `language_id` |
| `bits` | int | 16, 32, or 64, from `language_id` |
| `endianness` | string | `little` or `big`, from `language_id` |
| `filename` | string | Program name |
| `md5` | string | File MD5 hash; row omitted when the host reports none |
| `sha256` | string | File SHA-256 hash; row omitted when the host reports none |
| `program_name` | string | Program name |
| `program_path` | string | Program file path |
| `language_id` | string | Processor language (e.g. `x86:LE:64:default`) |
| `compiler_spec` | string | Compiler specification |
| `analysis_id` | string | Analysis session ID |
| `host_service` | string | RPC host service name (e.g. `ghidra`, `libghidra`) |
| `is_headless` | bool | Running in headless mode |
| `revision` | int | Program revision number (session write counter) |

```sql
SELECT * FROM binary;
SELECT value FROM binary WHERE key = 'revision';   -- write-cycle check
SELECT key, value FROM binary WHERE key IN ('processor','filetype','entry_point');
```

### runtime_settings
Writable live view over the per-connection runtime controls — schema
`(key TEXT, value TEXT, type TEXT, scope TEXT)`, one row per knob. Read a value
with `SELECT`, change it with `UPDATE runtime_settings SET value=... WHERE
key=...`. Only the `value` column is writable (for value settings);
`key`/`type`/`scope`, the read-only rows and the action verbs reject writes, and
INSERT/DELETE are rejected. `timeout_push`/`timeout_pop` remain PRAGMAs.

| Key | Type | Description |
|-----|------|-------------|
| `query_timeout_ms` | int | Per-query timeout in ms; `0` = no client-side timeout (ghidrasql default) |
| `queue_admission_timeout_ms` | int | Admission-queue wait budget in ms |
| `max_queue` | int | Max queued queries |
| `hints_enabled` | bool | Whether query hints/warnings are emitted |
| `timeout_stack_depth` | int | Current depth of the `timeout_push` stack |
| `max_timeout_stack_depth` | int | Push-stack cap (64) |
| `timeout_push` | action | `PRAGMA ghidrasql.timeout_push = <ms>` pushes a temporary timeout |
| `timeout_pop` | action | `PRAGMA ghidrasql.timeout_pop` restores the previous timeout |

```sql
SELECT key, value, type, scope FROM runtime_settings ORDER BY key;
UPDATE runtime_settings SET value='5000' WHERE key='query_timeout_ms';  -- set
SELECT value FROM runtime_settings WHERE key='query_timeout_ms';        -- read
PRAGMA ghidrasql.timeout_push = 30000;      -- scope a heavier timeout...
SELECT text FROM pseudocode WHERE func_addr = 0x401000;
PRAGMA ghidrasql.timeout_pop;               -- ...then restore
```

### Other Tables

Additional tables available for specialized analysis:

| Table | Description |
|-------|-------------|
| `memory_blocks` | Memory blocks with detailed permissions (is_read, is_write, is_exec) |
| `function_calls` | Aggregated function call summary (src/dst names, edge_count) |
| `function_locals` | Function local variables (stack-based analysis). Writable: UPDATE `name` / `local_type` (routes through the decompiler rename/retype path) |
| `xref_index` | Pre-attributed xref edges (`src_func_addr`, `dst_func_addr`, `from_addr`, `to_addr`, `kind`, `is_code`, `is_data`) — preferred surface for raw xrefs that need source/target function attribution without re-joining `funcs` |
| `stack_vars` | Stack variables from the listing-layer stack frame (`func_addr`, `var_id`, `name`, `var_type`, `stack_offset`, `size`, `is_param`). Served decompiler-free; filter with `WHERE func_addr = <addr>` to read one function's variables cheaply. |
| `register_vars` | Register variables |
| `function_frames` | Stack frame layout (`func_addr`, `frame_size`, `arg_size`, `local_size`, `saved_reg_size`, `stack_base_reg`, `has_frame_pointer`). Served decompiler-free from Ghidra's listing-layer stack frame. `stack_base_reg` is the compiler-spec **stack pointer** register name (e.g. `RSP`), not a frame-base register. **NULL semantics:** `saved_reg_size`, `stack_base_reg`, and `has_frame_pointer` are `NULL` when the engine does not expose them (they are never fabricated — a `NULL` means "unknown", not "zero/absent"). Filter with `WHERE func_addr = <addr>` to read one function's frame cheaply. |
| `function_chunks` | Function code chunks (for non-contiguous functions) |
| `loops` | Detected loop structures (header, latch, depth, kind) |
| `switch_tables` | Switch/case jump tables |
| `dominators` | Dominator tree for CFG analysis |
| `post_dominators` | Post-dominator tree |
| `tail_calls` | Tail call optimizations |
| `constants` | Constant value references |
| `equates` | Symbolic constants (equates) |
| `relocations` | Relocation entries |
| `function_metrics` | Function complexity metrics (instruction_count, block_count, cyclomatic_complexity, etc.) |
| `text_index` | Full-text search index |
| `search_index` | Search term index |
| `program_options` | Program settings |
| `analysis_passes` | Analysis history |
| `transactions` | Transaction log |
| `project_properties` | Project metadata |
| `project_files` | Project files and folders (`path`, `folder_path`, `content_type`, `is_program`) |
| `project_programs` | Program-only project files; use this before switching active programs |
| `sql_capabilities` | Feature capability matrix (includes `feature.runtime_settings`) |
| `runtime_settings` | Writable live view of runtime controls — `UPDATE value` to set; `timeout_push`/`timeout_pop` are PRAGMAs (see below) |
| `parity_findings` | Cross-tool parity analysis findings |
| `perf_benchmarks` | Performance benchmark results (writable: `INSERT`/`DELETE` persist in the program database). INSERT upserts by `bench_id` — re-inserting the same `bench_id` replaces the record; DELETE by `bench_id` is atomic host-side |
| `live_meta` | Live shared-host metadata |

---

## Convenience Views

### callgraph_edges
Call graph with function names resolved.

| Column | Type | Description |
|--------|------|-------------|
| `src_func_addr` | INT64 | Caller function address |
| `src_func_name` | TEXT | Caller function name |
| `dst_func_addr` | INT64 | Callee function address |
| `dst_func_name` | TEXT | Callee function name |
| `call_site` | INT64 | Call instruction address |

```sql
-- What does main call?
SELECT dst_func_name, printf('0x%X', dst_func_addr) as addr
FROM callgraph_edges WHERE src_func_name LIKE '%main%';
```

### callers
Who calls each function.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT64 | Target function address |
| `caller_addr` | INT64 | Xref source address |
| `caller_name` | TEXT | Calling function name |
| `caller_func_addr` | INT64 | Calling function start address |

```sql
-- Who calls function at 0x401000?
SELECT caller_name, printf('0x%X', caller_addr) as from_addr
FROM callers WHERE func_addr = 0x401000;

-- Most called functions
SELECT printf('0x%X', func_addr) as addr, COUNT(*) as caller_count
FROM callers GROUP BY func_addr ORDER BY caller_count DESC LIMIT 10;
```

### callees
What each function calls.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT64 | Calling function address |
| `func_name` | TEXT | Calling function name |
| `callee_addr` | INT64 | Called address |
| `callee_name` | TEXT | Called function name |

```sql
-- What does main call?
SELECT callee_name, printf('0x%X', callee_addr) as addr
FROM callees WHERE func_name LIKE '%main%';

-- Functions with most unique callees (highest fan-out)
SELECT func_name, COUNT(DISTINCT callee_addr) as unique_callees
FROM callees GROUP BY func_addr ORDER BY unique_callees DESC LIMIT 10;
```

### string_refs
String cross-references with function context.

| Column | Type | Description |
|--------|------|-------------|
| `string_addr` | INT64 | String address |
| `string_value` | TEXT | String content |
| `string_length` | INT64 | String length |
| `ref_addr` | INT64 | Reference address |
| `func_addr` | INT64 | Referencing function address |
| `func_name` | TEXT | Referencing function name |

```sql
-- Functions using error strings
SELECT func_name, string_value
FROM string_refs
WHERE string_value LIKE '%error%' OR string_value LIKE '%fail%';

-- Functions with most string references
SELECT func_name, COUNT(*) as string_count
FROM string_refs WHERE func_name IS NOT NULL
GROUP BY func_addr ORDER BY string_count DESC LIMIT 10;
```

### function_signatures
Function prototypes.

| Column | Type | Description |
|--------|------|-------------|
| `sig_id` | TEXT | Signature identifier |
| `func_addr` | INT64 | Function address |
| `func_name` | TEXT | Function name |
| `prototype` | TEXT | Full prototype |
| `calling_convention` | TEXT | Calling convention |
| `return_type` | TEXT | Return type |
| `param_count` | INT64 | Parameter count |
| `is_variadic` | INT | Variadic flag |

### decompiler_listing
Decompiled code with complexity metrics.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT64 | Function address |
| `func_name` | TEXT | Function name |
| `pseudocode` | TEXT | Pseudocode text |
| `token_count` | INT | Token count |
| `local_count` | INT | Local variable count |
| `hotness_score` | INT | Complexity/importance score |

### function_metrics_scored
Functions ranked by combined complexity/importance score.

| Column | Type | Description |
|--------|------|-------------|
| `func_addr` | INT64 | Function address |
| `func_name` | TEXT | Function name |
| `size` | INT64 | Function size |
| `instruction_count` | INT64 | Number of instructions |
| `block_count` | INT64 | Number of basic blocks |
| `cyclomatic_complexity` | INT64 | Cyclomatic complexity |
| `call_in_count` | INT64 | Incoming calls |
| `call_out_count` | INT64 | Outgoing calls |
| `string_ref_count` | INT64 | String references |
| `hotness_score` | INT64 | Score = (call_in*3 + call_out*2 + strings + complexity) |

```sql
-- Most "interesting" functions by hotness
SELECT func_name, printf('0x%X', func_addr) as addr, hotness_score
FROM function_metrics_scored ORDER BY hotness_score DESC LIMIT 15;
```

### type_layout
Types with member counts.

| Column | Type | Description |
|--------|------|-------------|
| `type_id` | TEXT | Type identifier |
| `name` | TEXT | Type name |
| `kind` | TEXT | Type kind |
| `size` | INT64 | Type size |
| `member_count` | INT | Struct/union member count |
| `enum_member_count` | INT | Enum member count |

### memory_hexdump
Hex dump view.

| Column | Type | Description |
|--------|------|-------------|
| `addr` | INT64 | Byte address |
| `byte_hex` | TEXT | Hex byte value (e.g., "4D") |
| `segment_name` | TEXT | Segment name |
| `func_addr` | INT64 | Containing function |
| `source_kind` | TEXT | Source type |

### Other Useful Views

| View | Description |
|------|-------------|
| `functions` | Simplified function view |
| `memory_layout` | Memory blocks with detailed flags |
| `string_hotspots` | Functions ranked by string reference count |
| `typed_data_items` | Data items with xref counts |
| `local_types` | Non-system types only |
| `function_call_stats` | Aggregated call statistics |
| `disasm_calls` | Disassembly call sites |

### Ctree Views (AST-like)

For advanced decompiler analysis, ghidrasql provides AST-like views. **Always filter by `func_addr`.**

| View | Description |
|------|-------------|
| `ctree` | Unified AST node tree |
| `ctree_lvars` | Decompiler locals (writable — UPDATE name/type routes to decomp_lvars) |
| `ctree_v_calls` | Call nodes with callee info |
| `ctree_v_loops` | Loop nodes (for, while, do) |
| `ctree_v_ifs` | If/else condition nodes |
| `ctree_v_comparisons` | Comparison operations |
| `ctree_v_assignments` | Assignment operations |
| `ctree_v_returns` | Return statement analysis |
| `ctree_v_derefs` | Pointer dereference operations |
| `ctree_v_calls_in_loops` | Calls inside loops |
| `ctree_v_calls_in_ifs` | Calls inside if blocks |
| `ctree_v_leaf_funcs` | Leaf functions (no outgoing calls) |
| `ctree_v_call_chains` | Recursive call chains (max depth 10) |

### Low-IR Views (`ir_ops` + `ir_v_*` + `ir_operands` + `ir_maturities`)

Cross-tool low-IR projection over `pcode_ops` — the same view names and columns hold
across the tool family, so portable SQL can join/compare IR across engines. **Always
filter by `func_addr`.** `sql_capabilities` advertises `feature.ir_ops` so portable SQL
can feature-detect the surface (`SELECT state FROM sql_capabilities WHERE feature = 'feature.ir_ops';`).

`ir_ops` is the canonical projection: `func_addr`, `seq`, `addr`, `op` (canonical
P-code), `native_op` (the engine's own opcode text — equal to `op` here, since Ghidra
P-code is the anchor vocabulary), `is_ssa` (maturity-dependent: high=1, raw=0), and the
passthrough `maturity` / `stage` filters. Add `AND maturity='raw'` to drop to raw P-code.

```sql
SELECT op, native_op, is_ssa, maturity FROM ir_ops WHERE func_addr = 0x401000 ORDER BY seq;
```

The `ir_v_*` **semantic views** classify the op stream engine-agnostically — each is
`func_addr`, `seq`, `addr`, `op`, scoped by `func_addr`:

| View | Selects |
|------|---------|
| `ir_v_calls` | CALL / CALLIND / CALLOTHER |
| `ir_v_mem_writes` | STORE |
| `ir_v_mem_reads` | LOAD |
| `ir_v_branches` | BRANCH / CBRANCH / BRANCHIND / RETURN |
| `ir_v_arith` | Integer/float arithmetic (INT_ADD, INT_SUB, FLOAT_MULT, ...) |

**`ir_operands`** projects `pcode_varnodes` (the 5-kind value operands): `func_addr`,
`op_seq`, `operand_index`, `role`, `kind`, `text` (= varnode space), `value` (= offset),
`size`; join `ir_operands.op_seq = ir_ops.seq`. **`ir_maturities`** advertises the P-code
ladder (`maturity`, `stage`, `ordinal`, `is_default`, `is_ssa` — 2 rows: `high` default, `raw`).

---

## SQL Functions

### Utility
| Function | Description |
|----------|-------------|
| `hex(value)` | Convert integer to hex string (e.g., `"0x1234"`) |
| `normalize_text(text)` | Normalize text for search (lowercase, alphanumeric, squashed whitespace) |

### Search
| Function | Description |
|----------|-------------|
| `search_match(haystack, query)` | Returns 1 if all query terms match haystack |
| `search_score(haystack, query)` | Compute term frequency relevance score |
| `search_snippet(text, query)` | Extract context snippet around first match (default radius: 48) |
| `search_snippet(text, query, radius)` | Extract snippet with custom radius |
| `search_rank(domain, text, query)` | Weighted search rank by domain |

### Type Analysis
| Function | Description |
|----------|-------------|
| `type_family(decl)` | Classify type: aggregate, enum, alias, function, pointer, boolean, floating, integral, void, unknown |
| `type_is_pointer(decl)` | Returns 1 if type is pointer or reference |
| `type_strip_cv(decl)` | Strip const/volatile qualifiers from type declaration |

### Decompiler Variable Mutation
| Function | Description |
|----------|-------------|
| `rename_local(func_addr, local_id, new_name)` | Rename decompiler local variable. Returns 1 on success. |
| `set_local_type(func_addr, local_id, new_type)` | Set decompiler local variable type. Returns 1 on success. |

**Note:** These functions are equivalent to `UPDATE decomp_lvars SET name/type`. Use whichever is more convenient.

### Type Import
| Function | Description |
|----------|-------------|
| `parse_decls(source_text)` | Parse C declarations and import them into Ghidra's type system. Returns count of newly created types. Uses Ghidra's CParser — standard C syntax only (no preprocessor, no `#include`). |

```sql
-- Import a single struct
SELECT parse_decls('typedef struct { int x; int y; } Point;');

-- Import multiple types at once (separate with \n)
SELECT parse_decls('typedef enum { OP_NONE=0, OP_INIT=1 } Opcode;
typedef struct { Opcode op; int value; } Command;');

-- Import types, then verify they exist
SELECT parse_decls('typedef struct { int flags; char tag[8]; } Session;');
SELECT name, kind, size FROM types WHERE name = 'Session';
```

**Key points:**
- Returns `0` if all types already existed (e.g., recovered from PDB)
- Returns `>0` for newly created types
- Standard C syntax only — no `#include`, no macros, no `#pragma`
- Supports: structs, unions, enums, typedefs, function pointer types
- Types are immediately available for use in `UPDATE funcs SET prototype = ...`

### Source / Lifecycle
| Function | Description |
|----------|-------------|
| `string_count()` | Get current string count from source |
| `rebuild_strings()` | Refresh string table and return count |
| `program_revision()` | Get Ghidra's native modification number for the current program |
| `save_database()` | **Save pending changes** to Ghidra project. Returns 1 on success. |
| `discard_changes()` | Discard all pending changes. Returns 1 on success. |
| `refresh_database()` | Refresh source live readers so the next query is rebuilt from fresh source state. Returns 1 on success. |

### Cache / Freshness Model

| Function | Description |
|----------|-------------|
| `cache_stats()` | Returns JSON: `cache_invalidations_total`, `last_seen_revision`, `source_revision`, `revision_tracked`, and the list of cacheable tables |
| `cache_invalidate(table)` | Drop one table's cache so the next read pulls fresh data. Most useful inside a batched script after a write. |
| `cache_invalidate_all()` | Drop every cached table |

GhidraSQL materializes virtual tables because decompiler-backed tables are expensive. With libghidra live sources, caches may persist across `/query` calls while the native freshness token is unchanged. The token includes `program_id`, Ghidra's `modification_number`, program path, and cheap project-file metadata when available, so program switches and Ghidra UI/API edits invalidate cached tables before reading.

For custom sources that do not expose a freshness token, GhidraSQL keeps the conservative behavior: every one-shot query invalidates table materialization. Inside multi-statement scripts, writes and freshness changes force invalidation before later reads. Use `refresh_database()` or `.refresh` when you want to force a full refresh.

---

## Write Operations Summary

### UPDATE Support (20+ writable columns)

| Table | Writable Columns |
|-------|-----------------|
| `funcs` | name, prototype |
| `names` | name |
| `comments` | comment, repeatable, source |
| `data_items` | name, data_type |
| `bytes` | value |
| `segments` | start_addr (rebase/move block) |
| `memory_blocks` | start_addr (rebase/move block) |
| `types` | name |
| `type_members` | member_name, member_type, comment |
| `type_enums` | name |
| `type_enum_members` | name, value, comment |
| `type_unions` | name |
| `type_aliases` | name, target_type |
| `signatures` | name (function rows only), prototype |
| `function_params` | param_name, param_type |
| `function_locals` | name, local_type |
| `decomp_lvars` | name, type |
| `decomp_comments` | comment, source |
| `breakpoints` | enabled, type, size, condition, group |
| `bookmarks` | type, category, comment |

**Note:** `function_tags` and `function_tag_mappings` are INSERT/DELETE only (no UPDATE).

### INSERT Support

| Table | Required Columns |
|-------|-----------------|
| `comments` | addr, comment (or source) |
| `decomp_comments` | addr, comment (or source) |
| `names` | addr, name |
| `data_items` | addr, data_type |
| `segments` | start_addr, end_addr [, name, perm] |
| `memory_blocks` | start_addr, end_addr [, name, perm] |
| `types` | name, kind [, size, declaration] |
| `type_members` | parent_type_id, member_name, member_type [, size] |
| `type_enums` | name [, width, is_signed] |
| `type_enum_members` | type_id, name, value |
| `type_unions` | name [, size, declaration] |
| `type_aliases` | name, target_type |
| `breakpoints` | addr [, enabled, type, size, condition, group] |
| `bookmarks` | addr [, type, category, comment] |
| `function_tags` | name [, comment] |
| `function_tag_mappings` | func_addr, tag_name |
| `perf_benchmarks` | bench_id [, query_family, dataset_profile, cold_ms_p50, cold_ms_p95, warm_ms_p50, warm_ms_p95, throughput_qps, regression_pct, status] — upserts by bench_id (re-inserting the same bench_id replaces the record) |

### DELETE Support

| Table | Deletes By |
|-------|-----------|
| `names` | Row match (addr + name) |
| `comments` | Row match (addr + source/repeatable) |
| `decomp_comments` | Row match (addr + source) |
| `data_items` | Row match (addr) |
| `segments` | Row match (start_addr) |
| `memory_blocks` | Row match (start_addr) |
| `types` | Row match (type_id) |
| `type_members` | Row match (parent_type_id + ordinal) |
| `type_enums` | Row match (type_id) |
| `type_enum_members` | Row match (type_id + ordinal) |
| `type_unions` | Row match (type_id) |
| `type_aliases` | Row match (type_id) |
| `breakpoints` | Row match (addr) |
| `bookmarks` | Row match (addr + type + category) |
| `function_tags` | Row match (name) |
| `function_tag_mappings` | Row match (func_addr + tag_name) |
| `perf_benchmarks` | Row match (bench_id); each row DELETE is one host-side RPC; DELETE with no WHERE removes all rows (one RPC per row) |

### Explicit Save Model

Changes are **not auto-saved**. After mutations, you must explicitly save:
```sql
SELECT save_database();
```

Or discard all pending changes:
```sql
SELECT discard_changes();
```

---

## Annotation Workflow

The complete recipe for annotating a function:

```sql
-- 1. Find the function
SELECT name, printf('0x%X', addr) as addr, size FROM funcs WHERE name LIKE '%FUN_004011f0%';

-- 2. Decompile to understand it
SELECT text FROM pseudocode WHERE func_addr = 0x4011F0;

-- 3. Look at its variables
SELECT local_id, name, type, storage FROM decomp_lvars WHERE func_addr = 0x4011F0;

-- 4. Look at its parameters
SELECT ordinal, param_name, param_type FROM function_params WHERE func_addr = 0x4011F0;

-- 5. Rename the function
UPDATE funcs SET name = 'parseConfig' WHERE addr = 0x4011F0;

-- 6. Set the function signature
UPDATE funcs SET prototype = 'bool parseConfig(const char* path, Config* out)' WHERE addr = 0x4011F0;

-- 7. Rename parameters
UPDATE function_params SET param_name = 'path' WHERE func_addr = 0x4011F0 AND ordinal = 0;
UPDATE function_params SET param_type = 'const char *' WHERE func_addr = 0x4011F0 AND ordinal = 0;

-- 8. Rename local variables (use local_id from step 3)
UPDATE decomp_lvars SET name = 'configFile' WHERE func_addr = 0x4011F0 AND local_id = '<local_id_from_step_3>';
UPDATE decomp_lvars SET type = 'FILE *' WHERE func_addr = 0x4011F0 AND local_id = '<local_id_from_step_3>';

-- 9. Add comments
INSERT INTO comments (addr, comment, source) VALUES (0x4011F0, 'Reads and parses config file', 'plate');

-- 10. Re-decompile to verify
SELECT text FROM pseudocode WHERE func_addr = 0x4011F0;

-- 11. Save changes
SELECT save_database();
```

**Key points:**
- Always decompile first to understand the function before renaming
- Use the exact `local_id` values returned by `decomp_lvars` — not variable names or guessed offsets
- Re-decompile after changes to verify they look correct
- Batch all mutations before calling `save_database()`
- Use `discard_changes()` if you make mistakes

---

## Common Query Patterns

### Most Called Functions
```sql
WITH caller_counts AS (
    SELECT to_addr, COUNT(*) as callers
    FROM xrefs WHERE is_code = 1 GROUP BY to_addr
)
SELECT f.name, printf('0x%X', f.addr) as addr, c.callers
FROM funcs f JOIN caller_counts c ON f.addr = c.to_addr
ORDER BY c.callers DESC LIMIT 10;
```

### String Analysis
```sql
-- Find functions referencing specific strings
SELECT func_name, string_value
FROM string_refs WHERE string_value LIKE '%password%';

-- String type distribution
SELECT type_name, COUNT(*) as cnt FROM strings GROUP BY type_name ORDER BY cnt DESC;
```

### Import Analysis
```sql
-- Module dependency breakdown
SELECT module, COUNT(*) as cnt FROM imports GROUP BY module ORDER BY cnt DESC;

-- Dangerous/suspicious imports
SELECT module, name FROM imports
WHERE name LIKE '%Shell%' OR name LIKE '%WinExec%' OR name LIKE '%CreateProcess%'
   OR name LIKE '%VirtualAlloc%' OR name IN ('strcpy', 'strcat', 'sprintf', 'gets');

-- Crypto-related
SELECT module, name FROM imports WHERE name LIKE '%Crypt%' OR name LIKE '%Hash%';

-- Network-related
SELECT module, name FROM imports
WHERE name LIKE '%socket%' OR name LIKE '%connect%' OR name LIKE '%send%'
   OR name LIKE '%recv%' OR name LIKE '%WSA%' OR name LIKE '%Http%';
```

### Bridge Functions (High Connectivity)
```sql
WITH caller_counts AS (
    SELECT to_addr as func_addr, COUNT(*) as caller_cnt
    FROM xrefs WHERE is_code = 1 GROUP BY to_addr
),
callee_counts AS (
    SELECT func_addr, COUNT(DISTINCT callee_addr) as callee_cnt
    FROM callees GROUP BY func_addr
)
SELECT f.name, COALESCE(cr.caller_cnt, 0) as callers, COALESCE(ce.callee_cnt, 0) as callees
FROM funcs f
LEFT JOIN caller_counts cr ON cr.func_addr = f.addr
LEFT JOIN callee_counts ce ON ce.func_addr = f.addr
WHERE COALESCE(cr.caller_cnt, 0) >= 5 AND COALESCE(ce.callee_cnt, 0) >= 5
ORDER BY (cr.caller_cnt * ce.callee_cnt) DESC LIMIT 20;
```

### Function Complexity
```sql
-- Most complex functions by cyclomatic complexity
SELECT func_name, printf('0x%X', func_addr) as addr,
       cyclomatic_complexity, block_count, instruction_count
FROM function_metrics
ORDER BY cyclomatic_complexity DESC LIMIT 15;
```

### Type System Exploration
```sql
-- All struct types with their member counts
SELECT name, size, member_count FROM type_layout WHERE kind = 'struct' ORDER BY member_count DESC;

-- View struct members
SELECT member_name, member_type, offset, size
FROM type_members WHERE parent_type_name = 'MyStruct' ORDER BY offset;

-- Enum values
SELECT name, value FROM type_enum_members WHERE type_id = 'some_id' ORDER BY value;
```

### Hex Address Formatting
```sql
-- Use printf for formatted hex
SELECT printf('0x%X', addr) as addr, name FROM funcs;

-- Or use the hex() function
SELECT hex(addr) as addr, name FROM funcs;
```

---

## REPL Commands

When running in interactive mode, these dot-commands are available:

| Command | Description |
|---------|-------------|
| `.tables` | List all SQL tables and views |
| `.schema <table>` | Show CREATE statement for table or view |
| `.info` | Show database metadata (program info, row counts, capabilities) |
| `.save` | Save pending changes (calls `save_database()`) |
| `.discard` | Discard pending changes (calls `discard_changes()`) |
| `.refresh` | Force source refresh and cache invalidation |
| `.http` | Show HTTP server status |
| `.http start` | Start HTTP server |
| `.http stop` | Stop HTTP server |
| `.help` / `.h` | Show help message |
| `.quit` / `.exit` / `.q` | Exit the REPL |

---

## Server Mode (HTTP REST)

GhidraSQL can run as an HTTP server for remote queries.

**Starting the server:**
```bash
# Start with HTTP server
ghidrasql --ghidra C:/ghidra_dist/ghidra_12.1_DEV --binary program.exe --http

# List programs in a multi-program project and exit
ghidrasql --ghidra C:/ghidra_dist/ghidra_12.1_DEV \
  --project C:/work/projects --project-name firmware --list-project-programs

# Import multiple binaries and make one project program active
ghidrasql --ghidra C:/ghidra_dist/ghidra_12.1_DEV \
  --project C:/work/projects --project-name firmware \
  --binary loader.exe --binary payload.exe --program /payload.exe --http

# Custom port and auth
ghidrasql --url http://localhost:18080 --http --port 9000 --auth mysecret
```

**Or from the REPL:**
```
.http start
```

**HTTP Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /query` | POST | Execute SQL query (body = raw SQL text) |
| `GET /status` | GET | Server status |
| `POST /refresh` | POST | Refresh database |
| `POST /save` | POST | Save changes |
| `POST /discard` | POST | Discard changes |

**Response format (JSON):**
```json
{
  "success": true,
  "statement_count": 1,
  "row_count_total": 1,
  "results": [
    {"success": true, "columns": ["name", "size"], "rows": [["main", "500"]], "row_count": 1,
     "elapsed_ms": 12, "partial": false, "timed_out": false}
  ]
}
```

Multi-statement bodies use the same shape with one entry per statement in `results[]`. On failure, top-level `success` is `false` with an `error` field; `results[]` holds the partial run up to the failing statement.

**Example with curl:**
```bash
curl -X POST http://localhost:8081/query -d "SELECT name, size FROM funcs LIMIT 5"

# With auth
curl -X POST http://localhost:8081/query -H "Authorization: Bearer mysecret" \
     -d "SELECT name FROM funcs LIMIT 5"
```

---

## Output Guidelines

### ALWAYS Show Actual Data

When the user asks to see something (decompilation, code, data), **ALWAYS include the actual output** in your response — don't just describe it.

**BAD:**
> "The function appears to call malloc and contains a loop..."

**GOOD:**
```c
int parseConfig(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) return -1;
    char buf[256];
    while (fgets(buf, 256, f) != NULL) {
        processLine(buf);
    }
    fclose(f);
    return 0;
}
```

### Addresses in Hex
Always display addresses in hex format using `printf('0x%X', addr)`.

### Batch Mutations Before Save
Group all your UPDATE/INSERT/DELETE operations together, then call `SELECT save_database()` once at the end.

### Decompilation Workflow
1. Run `SELECT text FROM pseudocode WHERE func_addr = <addr>`
2. Include the actual pseudocode output in a code block
3. Then optionally add analysis

### After Mutations, Re-decompile
After renaming variables or changing types, re-decompile to show the user the improved output:
```sql
-- After mutations...
SELECT text FROM pseudocode WHERE func_addr = 0x401000;
```

---

## CRITICAL REMINDERS (Quick Reference Card)

- **String content column = `content`** (NOT `value`)
- **Decompiler variables table = `decomp_lvars`** (NOT `hlil_vars`)
- **Pseudocode = single `text` column** (NOT per-line `line` + `line_num`)
- **Save = `SELECT save_database()`** (NOT `SELECT save()`)
- **Decompile = `SELECT text FROM pseudocode WHERE func_addr = addr`**
- **Function signature = `UPDATE funcs SET prototype = ...`** (the funcs prototype column; the `signatures` table also exposes `prototype`)
- **Always filter `pseudocode`, `decomp_lvars` by `func_addr` or exact `func_name`; filter `instructions` by `addr` range or `func_addr`**
- **xrefs has NO `from_func` column** — use `callers`/`callees`/`callgraph_edges` views
- **Comments need `source` column** for INSERT: `'eol'`, `'pre'`, `'post'`, `'plate'`
- **Changes are NOT auto-saved** — always call `save_database()` after mutations
- **Use `printf('0x%X', addr)` for hex addresses** in output
