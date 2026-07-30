// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ghidrasql::model {

struct ProgramInfoRow {
    std::string tool_name = "ghidra";
    std::string program_name;
    std::string program_path;
    std::string language_id;
    std::string compiler_spec;
    std::string analysis_id;
    std::string md5;
    std::string sha256;
    std::int64_t image_base = 0;
    int is_headless = 1;
    std::int64_t revision = 0;
    // Executable container format from the loader (empty when unreported).
    std::string executable_format;
    // Entry point; valid only when has_entry_point (0 is a valid address).
    std::int64_t entry_point = 0;
    bool has_entry_point = false;
};

// One `binary` table fact: the canonical key/value/type row shape shared
// across the tool family (idasql/bnsql/ghidrasql/r2sql).
struct BinaryFactRow {
    std::string key;
    std::string value;
    std::string type;  // "string", "hex", "bool", "int"
};

struct ProjectFileRow {
    std::string path;
    std::string name;
    std::string folder_path;
    std::string content_type;
    std::string domain_object_class;
    int is_folder = 0;
    int is_program = 0;
};

struct FunctionRow {
    std::int64_t address = 0;
    std::string name;
    std::int64_t size = 0;
    std::int64_t end_ea = 0;
    std::int64_t flags = 0;
    std::string namespace_name;
    std::string signature;
    // Ghidra's authoritative Function.getParameterCount() (excludes the varargs
    // "..."). funcs.arg_count reads this instead of splitting the prototype string.
    std::int64_t param_count = 0;
};

struct SegmentRow {
    std::int64_t start_ea = 0;
    std::int64_t end_ea = 0;
    std::string name;
    std::string segment_class;
    int perm = 0;
    int bitness = 0;
};

struct MemoryBlockRow {
    std::int64_t start_ea = 0;
    std::int64_t end_ea = 0;
    std::string name;
    std::string block_class;
    int perm = 0;
    int bitness = 0;
    std::int64_t size = 0;
    int is_read = 0;
    int is_write = 0;
    int is_exec = 0;
    // 1 = the block carries initialized (readable) bytes; 0 = uninitialized
    // (.bss / freshly created). Drives the memory_bytes derivation: initialized
    // blocks are read via paged read_bytes, uninitialized ones emit NULL-value
    // rows from this metadata alone.
    int is_initialized = 1;
};

struct MemoryByteRow {
    std::int64_t address = 0;
    // Byte value 0-255. Meaningful only when is_initialized == 1; for an
    // uninitialized byte the SQL `value` column reports NULL (the "byte is
    // unknown" state, distinct from an initialized byte that happens to be 0).
    int value = 0;
    std::string segment_name;
    std::int64_t func_addr = 0;
    std::string source_kind;
    std::int64_t item_addr = 0;
    std::int64_t item_offset = 0;
    int is_printable = 0;
    std::string ascii;
    // 1 = the byte is a mapped, initialized byte with a known value; 0 = the byte
    // is mapped but uninitialized (e.g. a .bss/created block) — `value` is NULL,
    // is_printable is 0 and `ascii` is empty. Named like data_items.is_initialized.
    int is_initialized = 1;
};

struct SymbolRow {
    std::int64_t address = 0;
    std::string name;
    std::string symbol_kind;
    std::string namespace_name;
    int is_primary = 1;
    int is_external = 0;
    // Ghidra Symbol.isExternalEntryPoint(): true for program entry/export
    // symbols. Source metadata for deriving `entries`, not a public `names`
    // column.
    int is_external_entry_point = 0;
};

struct ImportRow {
    std::int64_t address = 0;
    std::string name;
    std::string module;
};

struct ExportRow {
    std::int64_t address = 0;
    std::string name;
    std::string module;
};

struct StringRow {
    std::int64_t address = 0;
    std::int64_t length = 0;
    std::string type;
    std::string encoding;
    std::string content;
};

struct XrefRow {
    std::int64_t from_ea = 0;
    std::int64_t to_ea = 0;
    std::string kind;
    int is_code = 0;
    int is_data = 0;
};

struct CallEdgeRow {
    std::int64_t src_func_addr = 0;
    std::int64_t call_site = 0;
    std::int64_t dst_addr = 0;
    std::int64_t dst_func_addr = 0;
    std::string kind;
};

struct FunctionCallRow {
    std::int64_t src_func_addr = 0;
    std::string src_func_name;
    std::int64_t dst_func_addr = 0;
    std::string dst_func_name;
    std::int64_t edge_count = 0;
};

struct BlockRow {
    std::int64_t func_addr = 0;
    std::int64_t start_ea = 0;
    std::int64_t end_ea = 0;
    int in_degree = 0;
    int out_degree = 0;
};

struct InstructionRow {
    std::int64_t address = 0;
    std::string mnemonic;
    std::string operands;
    std::string disasm;
    int size = 0;
    std::string bytes;
    // Start address of the containing function (canonical `func_addr`), or 0 when
    // the instruction falls outside any known function body. Derived in C++ by
    // range-mapping `address` against the function set (see assign_instruction_func_addrs).
    std::int64_t func_addr = 0;
};

struct InstructionOperandRow {
    std::int64_t address = 0;    // instruction address (canonical `addr`)
    std::int64_t func_addr = 0;  // containing function, derived in C++ by range-mapping `address`
    int operand_index = 0;       // 0-based operand position
    std::string text;            // rendered per-operand representation
    std::string type_name;       // register / immediate / memory / address / ...
    std::string ref_type;        // RefType (READ / WRITE / READ_WRITE / DATA / ...)
};

struct CommentRow {
    std::int64_t address = 0;
    std::string comment;
    int repeatable = 0;
    std::string source;
};

struct DataItemRow {
    std::int64_t address = 0;
    std::string name;
    std::string data_type;
    std::int64_t size = 0;
    std::string value_repr;
    std::string segment_name;
    int is_string = 0;
    int is_initialized = 1;
};

struct FunctionLocalRow {
    std::int64_t func_addr = 0;
    std::string local_id;
    std::string name;
    std::string local_type;
    std::string storage;
    std::int64_t stack_offset = 0;
    std::int64_t size = 0;
};

struct StackVarRow {
    std::int64_t func_addr = 0;
    std::string var_id;
    std::string name;
    std::string var_type;
    std::int64_t stack_offset = 0;
    std::int64_t size = 0;
    int is_param = 0;
};

struct RegisterVarRow {
    std::int64_t func_addr = 0;
    std::string var_id;
    std::string name;
    std::string var_type;
    std::string reg_name;
    std::int64_t size = 0;
    int is_param = 0;
};

struct FunctionChunkRow {
    std::int64_t func_addr = 0;
    std::string chunk_id;
    std::int64_t start_ea = 0;
    std::int64_t end_ea = 0;
    std::string chunk_kind;
    int is_primary = 0;
};

struct TailCallRow {
    std::int64_t src_func_addr = 0;
    std::int64_t call_site = 0;
    std::int64_t dst_addr = 0;
    std::int64_t dst_func_addr = 0;
    std::string tail_kind;
};

struct ProgramOptionRow {
    std::string option_key;
    std::string option_value;
    std::string value_type;
    std::string option_scope;
};

struct AnalysisPassRow {
    std::int64_t pass_id = 0;
    std::string pass_name;
    std::string status;
    std::int64_t started_unix = 0;
    std::int64_t ended_unix = 0;
    std::string notes;
};

struct TransactionRow {
    std::int64_t tx_id = 0;
    std::string tx_name;
    std::string tx_kind;
    std::int64_t start_revision = 0;
    std::int64_t end_revision = 0;
    int committed = 0;
};

struct ProjectPropertyRow {
    std::string property_key;
    std::string property_value;
    std::string property_scope;
};

struct RelocationRow {
    std::int64_t address = 0;
    std::int64_t target_addr = 0;
    std::string reloc_type;
    std::int64_t width = 0;
    std::string symbol_name;
};

struct ConstantRow {
    std::int64_t address = 0;
    std::int64_t func_addr = 0;
    std::int64_t value = 0;
    std::int64_t width = 0;
    std::string repr;
    std::string source_kind;
};

struct EquateRow {
    std::string equate_id;
    std::string name;
    std::int64_t value = 0;
    std::int64_t width = 0;
    std::string domain;
};

struct TypeRow {
    std::string type_id;
    std::string name;
    std::string kind;
    std::int64_t size = 0;
    std::string declaration;
};

struct TypeMemberRow {
    std::string parent_type_id;
    std::string parent_type_name;
    std::string member_name;
    std::string member_type;
    std::int64_t offset = 0;
    std::int64_t size = 0;
    std::int64_t ordinal = 0;
    std::string comment;
};

struct TypeEnumRow {
    std::string type_id;
    std::string name;
    std::int64_t width = 0;
    int is_signed = 0;
    std::string declaration;
};

struct TypeEnumMemberRow {
    std::string type_id;
    std::string name;
    std::int64_t value = 0;
    std::int64_t ordinal = 0;
    std::string comment;
};

struct TypeUnionRow {
    std::string type_id;
    std::string name;
    std::int64_t size = 0;
    std::string declaration;
};

struct TypeAliasRow {
    std::string type_id;
    std::string name;
    std::string target_type;
    std::string declaration;
};

struct SignatureRow {
    std::string sig_id;
    std::string owner_kind;
    std::int64_t owner_addr = 0;
    std::string name;
    std::string prototype;
    std::string calling_convention;
    int is_variadic = 0;
    std::string return_type;
    std::int64_t param_count = 0;
};

struct FunctionParamRow {
    std::int64_t func_addr = 0;
    std::int64_t ordinal = 0;
    std::string param_name;
    std::string param_type;
    std::string storage;
    int is_user_named = 0;
};

struct FunctionFrameRow {
    std::int64_t func_addr = 0;
    std::int64_t frame_size = 0;
    std::int64_t arg_size = 0;
    std::int64_t local_size = 0;
    std::int64_t saved_reg_size = 0;
    std::string stack_base_reg;
    // Tri-state: 1 = has FP, 0 = no FP, -1 = unknown (surfaced as SQL NULL).
    int has_frame_pointer = -1;
    // When false, saved_reg_size is unknown and surfaces as SQL NULL. An empty
    // stack_base_reg likewise surfaces as NULL. The decompiler-free listing-layer
    // read (read_stack_frames) fills frame_size/local_size/arg_size honestly but
    // leaves saved_reg_size unknown; the decompiler fallback also leaves these
    // unknown rather than fabricating 16/"rbp"/1.
    bool saved_reg_size_known = false;
};

struct TextIndexRow {
    std::string doc_id;
    std::string domain;
    std::int64_t address = 0;
    std::int64_t func_addr = 0;
    std::string text;
    std::string norm_text;
};

struct SearchIndexRow {
    std::string term;
    std::string domain;
    std::string doc_id;
    std::int64_t address = 0;
    std::int64_t func_addr = 0;
    std::int64_t hit_count = 0;
    double rank = 0.0;
};

struct XrefIndexRow {
    std::int64_t from_ea = 0;
    std::int64_t to_ea = 0;
    std::int64_t src_func_addr = 0;
    std::int64_t dst_func_addr = 0;
    std::string kind;
    int is_code = 0;
    int is_data = 0;
};

struct CfgEdgeRow {
    std::int64_t func_addr = 0;
    std::int64_t src_start_ea = 0;
    std::int64_t dst_start_ea = 0;
    std::string edge_kind;
};

struct LoopRow {
    std::int64_t func_addr = 0;
    std::int64_t header_ea = 0;
    std::int64_t latch_ea = 0;
    std::int64_t start_ea = 0;
    std::int64_t end_ea = 0;
    int depth = 1;
    std::string loop_kind;
    std::int64_t block_count = 0;
};

struct SwitchTableRow {
    std::int64_t func_addr = 0;
    std::int64_t instr_ea = 0;
    std::int64_t table_ea = 0;
    std::int64_t min_case = 0;
    std::int64_t max_case = 0;
    std::int64_t case_count = 0;
    std::int64_t default_ea = 0;
};

struct DominatorRow {
    std::int64_t func_addr = 0;
    std::int64_t node_ea = 0;
    std::int64_t idom_ea = 0;
    int depth = 0;
    int is_entry = 0;
};

struct PostDominatorRow {
    std::int64_t func_addr = 0;
    std::int64_t node_ea = 0;
    std::int64_t ipdom_ea = 0;
    int depth = 0;
    int is_exit = 0;
};

struct FunctionMetricRow {
    std::int64_t func_addr = 0;
    std::string func_name;
    std::int64_t size = 0;
    std::int64_t instruction_count = 0;
    std::int64_t block_count = 0;
    std::int64_t edge_count = 0;
    std::int64_t cyclomatic_complexity = 1;
    std::int64_t call_in_count = 0;
    std::int64_t call_out_count = 0;
    std::int64_t string_ref_count = 0;
    std::int64_t token_count = 0;
};

struct PseudocodeRow {
    std::int64_t func_addr = 0;
    std::string func_name;
    std::string text;
    int is_stale = 0;
};

// One high-P-code (SSA) op — the Ghidra leg of the cross-tool low-level IR. `op` is the
// raw PcodeOp mnemonic (COPY, INT_ADD, MULTIEQUAL, ...); the canonical op naming happens
// in the unified ir_ops. Per-function (filter by func_addr).
// P-code maturity rung (engine-agnostic; the libghidra source maps it to the RPC enum).
enum class PcodeMaturity { High, Raw };

struct PcodeOpRow {
    std::int64_t func_addr = 0;
    int seq = 0;
    std::int64_t addr = 0;      // source machine address (valid when has_addr != 0)
    int has_addr = 0;
    std::string op;
    int has_output = 0;
    std::string output_kind;    // canonical operand kind (empty when no output)
    int output_size = 0;
    int input_count = 0;
    int is_ssa = 1;             // 1 for high (SSA) p-code, 0 for raw
    std::string maturity;       // returned rung: "high" | "raw"
    std::string stage;          // canonical stage: "ssa" (high) | "raw"
};

// One row per P-code VALUE operand (varnode) — output + inputs of every op. The
// canonical `kind` (reg/imm/mem/result/var) arrives already-modeled from the GetPcode RPC.
struct PcodeVarnodeRow {
    std::int64_t func_addr = 0;
    int op_seq = 0;             // owning op's seq (joins pcode_ops.seq)
    int operand_index = 0;      // varnode order within the op (output first, then inputs)
    std::string role;           // "out" (output varnode) | "in" (input varnode)
    std::string kind;           // reg | imm | mem | result | var
    std::string space;          // address space (register / const / ram / unique / stack)
    std::int64_t offset = 0;
    int size = 0;
    std::string maturity;
    std::string stage;
};

struct DecompLvarRow {
    std::int64_t func_addr = 0;
    std::string local_id;
    std::string name;
    std::string type;
    std::string storage;
    std::string role;
    std::string func_name;
};

struct DecompTokenRow {
    std::int64_t func_addr = 0;
    std::int64_t token_index = 0;
    std::string text;
    std::string kind;         // keyword/variable/type/function/parameter/global/const/comment/default/error/special
    int line = 0;
    int column = 0;
    std::string var_name;     // non-empty for variable/parameter tokens
    std::string var_type;
    std::string var_storage;
};

struct DecompilationDetail {
    std::int64_t func_addr = 0;
    std::string func_name;
    std::string prototype;
    std::string pseudocode;
    bool completed = false;
    bool is_fallback = false;
    std::string error_message;
    std::vector<DecompLvarRow> locals;
    std::vector<DecompTokenRow> tokens;
};

struct DecompCommentRow {
    std::int64_t func_addr = 0;
    std::int64_t address = 0;
    std::string comment;
    std::string source;
};

struct BreakpointRow {
    std::int64_t address = 0;
    int enabled = 1;
    int type = 0;
    std::int64_t size = 1;
    std::int64_t flags = 0;
    int pass_count = 0;
    std::string condition;
    std::string group;
    int loc_type = 0;
};

struct BookmarkRow {
    std::int64_t address = 0;
    std::string type;
    std::string category;
    std::string comment;
};

struct FunctionTagRow {
    std::string name;
    std::string comment;
};

struct FunctionTagMappingRow {
    std::int64_t func_addr = 0;
    std::string tag_name;
};

struct CapabilityRow {
    std::string area;
    std::string feature;
    std::string state;
    std::string notes;
    std::string since_rev;
};

struct ParityFindingRow {
    std::string finding_id;
    std::string source_suite;
    std::string source_test;
    std::string category;
    std::string severity;
    std::string status;
    std::string owner;
    std::string notes;
};

struct PerfBenchmarkRow {
    std::string bench_id;
    std::string query_family;
    std::string dataset_profile;
    double cold_ms_p50 = 0.0;
    double cold_ms_p95 = 0.0;
    double warm_ms_p50 = 0.0;
    double warm_ms_p95 = 0.0;
    double throughput_qps = 0.0;
    double regression_pct = 0.0;
    std::string status;
};

struct LiveMetaRow {
    std::string live_id;
    std::string source_mode;
    std::string program_id;
    std::int64_t revision = 0;
    std::string created_at;
    std::string row_counts_json;
    std::string lineage;
};

}  // namespace ghidrasql::model

namespace ghidrasql {

struct SourceFreshnessToken {
    std::string program_id;
    std::int64_t modification_number = 0;
    std::string program_path;
    std::string file_id;
    std::int64_t file_version = 0;
    std::int64_t file_last_modified_time = 0;

    bool operator==(const SourceFreshnessToken& other) const {
        return program_id == other.program_id &&
            modification_number == other.modification_number &&
            program_path == other.program_path &&
            file_id == other.file_id &&
            file_version == other.file_version &&
            file_last_modified_time == other.file_last_modified_time;
    }

    bool operator!=(const SourceFreshnessToken& other) const {
        return !(*this == other);
    }
};

class Source;

struct LibGhidraSourceOptions {
    std::string base_url = "http://127.0.0.1:18080";
    std::string auth_token;
    bool auto_open_program = false;
    std::string project_path;
    std::string project_name;
    std::string program_path;
    bool analyze = false;
    bool read_only = false;
    int auto_save_interval = 0;  // 0 = disabled; N > 0 = save every N mutations
    // HTTP read timeout for libghidra RPCs (per-call wall-clock budget).
    // 0 = use libghidra's default (120s). Tune lower (e.g. 30000) when
    // you'd rather have a wedged RPC fail fast and free the worker than
    // wait the full 2-minute default.
    int read_timeout_ms = 0;
};

struct SourceCallbacks {
    std::function<bool(std::vector<model::ProjectFileRow>&)> read_project_files;
    std::function<bool(std::vector<model::FunctionRow>&)> read_functions;
    std::function<bool(std::int64_t, model::FunctionRow&)> read_function_at;
    std::function<bool(std::vector<model::SegmentRow>&)> read_segments;
    std::function<bool(std::vector<model::SymbolRow>&)> read_symbols;
    std::function<bool(std::int64_t, std::vector<model::SymbolRow>&)> read_symbols_at;
    std::function<bool(std::vector<model::ImportRow>&)> read_imports;
    std::function<bool(std::vector<model::ExportRow>&)> read_exports;
    std::function<bool(std::vector<model::StringRow>&)> read_strings;
    std::function<bool(std::int64_t, std::vector<model::StringRow>&)> read_strings_at;
    // Windowed string read: (start_address, end_address, out). end_address is
    // INCLUSIVE (matching read_comments_in_range); returns every string whose
    // covered byte span intersects [start_address, end_address]. Optional; when
    // unset the callback source falls back to the base filter-the-bulk-read
    // default. Used by the streaming memory_bytes derivation.
    std::function<bool(std::int64_t, std::int64_t, std::vector<model::StringRow>&)> read_strings_in_range;
    // Raw memory bytes at [address, address+length). Optional; when unset the
    // callback source falls back to the base (unsupported) behavior. The
    // memory_bytes derivation uses it to materialize initialized data / filler
    // bytes and to read string bytes exactly. Must return false for
    // unmapped/uninitialized ranges (so uninitialized bytes stay NULL-valued).
    std::function<bool(std::int64_t, std::int64_t, std::vector<std::uint8_t>&)> read_bytes;
    std::function<bool(std::vector<model::XrefRow>&)> read_xrefs;
    std::function<bool(std::vector<model::FunctionCallRow>&)> read_function_calls;
    std::function<bool(std::vector<model::CallEdgeRow>&)> read_call_edges;
    std::function<bool(std::vector<model::MemoryBlockRow>&)> read_memory_blocks;
    std::function<bool(std::vector<model::DataItemRow>&)> read_data_items;
    std::function<bool(std::int64_t, std::vector<model::DataItemRow>&)> read_data_items_at;
    // Windowed data-item read; end_address INCLUSIVE, span-intersection
    // semantics (see read_strings_in_range).
    std::function<bool(std::int64_t, std::int64_t, std::vector<model::DataItemRow>&)> read_data_items_in_range;
    std::function<bool(std::vector<model::BlockRow>&)> read_blocks;
    std::function<bool(std::vector<model::CfgEdgeRow>&)> read_cfg_edges;
    std::function<bool(std::vector<model::SwitchTableRow>&)> read_switch_tables;
    std::function<bool(std::vector<model::DominatorRow>&)> read_dominators;
    std::function<bool(std::vector<model::PostDominatorRow>&)> read_post_dominators;
    std::function<bool(std::vector<model::LoopRow>&)> read_loops;
    // Decompiler-free stack-frame layout from the listing-layer StackFrame.
    std::function<bool(std::vector<model::FunctionFrameRow>&)> read_stack_frames;
    std::function<bool(std::int64_t, std::int64_t, std::vector<model::FunctionFrameRow>&)>
        read_stack_frames_in_range;
    // Decompiler-free stack variables (embedded in each frame's StackFrame).
    std::function<bool(std::vector<model::StackVarRow>&)> read_stack_vars;
    std::function<bool(std::int64_t, std::int64_t, std::vector<model::StackVarRow>&)>
        read_stack_vars_in_range;
    std::function<bool(std::vector<model::FunctionParamRow>&)> read_function_params;
    std::function<bool(std::vector<model::InstructionRow>&)> read_instructions;
    std::function<bool(std::int64_t, model::InstructionRow&)> read_instruction_at;
    // Windowed instruction read; end_address INCLUSIVE, span-intersection
    // semantics (see read_strings_in_range).
    std::function<bool(std::int64_t, std::int64_t, std::vector<model::InstructionRow>&)> read_instructions_in_range;
    std::function<bool(std::vector<model::InstructionOperandRow>&)> read_instruction_operands;
    std::function<bool(std::int64_t, std::int64_t, std::vector<model::InstructionOperandRow>&)> read_instruction_operands_in_range;
    std::function<bool(std::vector<model::CommentRow>&)> read_comments;
    std::function<bool(std::int64_t, std::vector<model::CommentRow>&)> read_comments_at;
    std::function<bool(std::int64_t, std::int64_t, std::vector<model::CommentRow>&)> read_comments_in_range;
    std::function<bool(std::vector<model::TypeRow>&)> read_types;
    std::function<bool(std::vector<model::TypeMemberRow>&)> read_type_members;
    std::function<bool(std::vector<model::TypeEnumRow>&)> read_type_enums;
    std::function<bool(std::vector<model::TypeEnumMemberRow>&)> read_type_enum_members;
    std::function<bool(std::vector<model::TypeUnionRow>&)> read_type_unions;
    std::function<bool(std::vector<model::TypeAliasRow>&)> read_type_aliases;
    std::function<bool(std::vector<model::SignatureRow>&)> read_signatures;
    std::function<bool(std::vector<model::BreakpointRow>&)> read_breakpoints;
    std::function<bool(std::int64_t, std::vector<model::BreakpointRow>&)> read_breakpoints_at;
    std::function<bool(std::vector<model::BookmarkRow>&)> read_bookmarks;
    std::function<bool(std::int64_t, std::vector<model::BookmarkRow>&)> read_bookmarks_at;
    std::function<bool(std::vector<model::FunctionTagRow>&)> read_function_tags;
    std::function<bool(std::vector<model::FunctionTagMappingRow>&)> read_function_tag_mappings;
    std::function<bool(model::ProgramInfoRow&)> read_program_info;
    std::function<bool(SourceFreshnessToken&)> read_freshness_token;
    std::function<bool(std::int64_t&)> read_program_revision;
    std::function<bool(std::vector<model::PseudocodeRow>&)> read_pseudocode;
    std::function<bool(std::vector<model::DecompLvarRow>&)> read_decomp_lvars;
    std::function<bool(std::vector<model::DecompCommentRow>&)> read_decomp_comments;
    std::function<bool(std::vector<model::DecompTokenRow>&)> read_decomp_tokens;
    std::function<bool(std::vector<model::CapabilityRow>&)> read_capabilities;
    std::function<bool(std::vector<model::ParityFindingRow>&)> read_parity_findings;
    std::function<bool(std::vector<model::PerfBenchmarkRow>&)> read_perf_benchmarks;
    std::function<bool(std::vector<model::LiveMetaRow>&)> read_live_meta;
    std::function<bool(std::int64_t, const std::string&)> rename_function;
    std::function<bool(std::int64_t, const std::string&)> rename_symbol;
    std::function<bool(std::int64_t, const std::string&)> delete_symbol;
    std::function<bool(std::int64_t, const std::string&)> rename_data_item;
    std::function<bool(std::int64_t, const std::string&)> set_data_item_type;
    std::function<bool(std::int64_t)> delete_data_item;
    std::function<bool(std::int64_t, const std::string&, bool)> set_comment;
    std::function<bool(std::int64_t, bool)> delete_comment;
    std::function<bool(std::int64_t, const std::string&, const std::string&)> set_comment_by_kind;
    std::function<bool(std::int64_t, const std::string&)> delete_comment_by_kind;
    std::function<bool(std::int64_t, const std::string&, const std::string&)> rename_decomp_local;
    std::function<bool(std::int64_t, const std::string&, const std::string&)> set_decomp_local_type;
    std::function<bool(std::int64_t, std::int64_t, const std::string&)> rename_function_param;
    std::function<bool(std::int64_t, std::int64_t, const std::string&)> set_function_param_type;
    std::function<bool(std::int64_t, int, std::int64_t, const std::string&, const std::string&)> add_breakpoint;
    std::function<bool(std::int64_t, bool)> set_breakpoint_enabled;
    std::function<bool(std::int64_t, int)> set_breakpoint_type;
    std::function<bool(std::int64_t, std::int64_t)> set_breakpoint_size;
    std::function<bool(std::int64_t, const std::string&)> set_breakpoint_condition;
    std::function<bool(std::int64_t, const std::string&)> set_breakpoint_group;
    std::function<bool(std::int64_t)> delete_breakpoint;
    std::function<bool(std::int64_t, const std::string&, const std::string&, const std::string&)> add_bookmark;
    std::function<bool(std::int64_t, const std::string&, const std::string&, const std::string&)> set_bookmark_type;
    std::function<bool(std::int64_t, const std::string&, const std::string&, const std::string&)> set_bookmark_category;
    std::function<bool(std::int64_t, const std::string&, const std::string&, const std::string&)> set_bookmark_comment;
    std::function<bool(std::int64_t, const std::string&, const std::string&)> delete_bookmark;
    std::function<bool(const model::PerfBenchmarkRow&)> add_perf_benchmark;
    std::function<bool(const std::string&)> delete_perf_benchmark;
    std::function<bool(const std::string&, const std::string&)> create_function_tag;
    std::function<bool(const std::string&)> delete_function_tag;
    std::function<bool(std::int64_t, const std::string&)> tag_function;
    std::function<bool(std::int64_t, const std::string&)> untag_function;
    std::function<bool(const std::string&, const std::string&)> rename_type;
    std::function<bool(const std::string&, const std::string&, std::int64_t, const std::string&)> create_type;
    std::function<bool(const std::string&)> delete_type;
    std::function<bool(const std::string&, const std::string&)> create_type_alias;
    std::function<bool(const std::string&)> delete_type_alias;
    std::function<bool(const std::string&, const std::string&)> set_type_alias_target;
    std::function<bool(const std::string&, std::int64_t, bool)> create_type_enum;
    std::function<bool(const std::string&)> delete_type_enum;
    std::function<bool(const std::string&, const std::string&, std::int64_t)> add_type_enum_member;
    std::function<bool(const std::string&, std::int64_t)> delete_type_enum_member;
    std::function<bool(const std::string&, std::int64_t, const std::string&)> rename_type_member;
    std::function<bool(const std::string&, const std::string&, const std::string&, std::int64_t)> add_type_member;
    std::function<bool(const std::string&, std::int64_t)> delete_type_member;
    std::function<bool(const std::string&, std::int64_t, const std::string&)> set_type_member_type;
    std::function<bool(const std::string&, std::int64_t, const std::string&)> rename_type_enum_member;
    std::function<bool(const std::string&, std::int64_t, std::int64_t)> set_type_enum_member_value;
    std::function<bool(const std::string&, std::int64_t, const std::string&)> set_type_member_comment;
    std::function<bool(const std::string&, std::int64_t, const std::string&)> set_type_enum_member_comment;
    std::function<bool(const std::string&, std::int64_t, const std::string&)> create_type_union;
    std::function<bool(const std::string&)> delete_type_union;
    std::function<bool(std::int64_t, const std::string&)> set_function_signature;
    std::function<bool(std::int64_t, const std::string&)> create_symbol;
    std::function<bool(std::int64_t, const std::string&, const std::string&)> create_data_item;
    std::function<bool(std::int64_t, std::uint8_t)> write_byte;
    std::function<bool(std::int64_t, std::int64_t, const std::string&, int, bool)> create_memory_block;
    std::function<bool(std::int64_t)> remove_memory_block;
    std::function<bool(std::int64_t, std::int64_t)> move_memory_block;
    std::function<bool()> save_database;
    std::function<bool()> discard_changes;
    std::function<bool()> refresh;
    std::function<int(const std::string&)> parse_declarations;
    std::function<std::string(std::int64_t)> decompile;
    std::function<std::optional<model::DecompilationDetail>(std::int64_t)> decompile_detail;
};

std::shared_ptr<Source> create_libghidra_live_source(const LibGhidraSourceOptions& options);
std::shared_ptr<Source> create_callback_live_source(SourceCallbacks callbacks);

// Map a single address to the start address of its containing function, using
// Ghidra getFunctionContaining semantics: the function `f` with the greatest
// `f.address <= addr` whose body still covers `addr` (`addr < f.address + size`,
// where the body end is `end_ea` when present, else `address + size`). Returns 0
// when no known function contains the address. `funcs` need not be sorted.
std::int64_t containing_func_addr(
    const std::vector<model::FunctionRow>& funcs, std::int64_t addr);

// Populate `func_addr` on every instruction by range-mapping its address against
// `funcs`. Sorts an internal copy once (O(n log n + m log n)); the input vectors
// are otherwise untouched. Instructions outside any function get func_addr = 0.
void assign_instruction_func_addrs(
    const std::vector<model::FunctionRow>& funcs,
    std::vector<model::InstructionRow>& instructions);

// Same range-mapping for operand rows (each operand sits at its instruction's addr).
void assign_operand_func_addrs(
    const std::vector<model::FunctionRow>& funcs,
    std::vector<model::InstructionOperandRow>& operands);

// Byte spans used by the *_in_range readers (and the memory_bytes derivation)
// to decide whether an item's covered bytes intersect an address window.
// Always >= 1 (an item covers at least its own start address).
//   instruction: max(size, decoded-hex byte count)
//   string:      length when > 0, else the decoded content size
//   data item:   size when > 0
std::int64_t instruction_byte_span(const model::InstructionRow& row);
std::int64_t string_byte_span(const model::StringRow& row);
std::int64_t data_item_byte_span(const model::DataItemRow& row);

// True when the `span` bytes starting at `item_start` intersect the INCLUSIVE
// signed-int64 address window [start_address, end_address]. The item's end is
// clamped on signed overflow (an absurd span never wraps past INT64_MAX).
bool byte_span_intersects_range(
    std::int64_t item_start,
    std::int64_t span,
    std::int64_t start_address,
    std::int64_t end_address);

class Source {
public:
    virtual ~Source() = default;

    // Last error message from a failed write operation (empty if none).
    virtual std::string last_error() const;

    // Direct live row readers. Default implementation returns false (no data).
    virtual bool read_project_files(std::vector<model::ProjectFileRow>& out) const;
    virtual bool read_functions(std::vector<model::FunctionRow>& out) const;
    virtual bool read_function_at(std::int64_t address, model::FunctionRow& out) const;
    virtual bool read_segments(std::vector<model::SegmentRow>& out) const;
    virtual bool read_symbols(std::vector<model::SymbolRow>& out) const;
    virtual bool read_symbols_at(std::int64_t address, std::vector<model::SymbolRow>& out) const;
    virtual bool read_imports(std::vector<model::ImportRow>& out) const;
    virtual bool read_exports(std::vector<model::ExportRow>& out) const;
    virtual bool read_strings(std::vector<model::StringRow>& out) const;
    virtual bool read_strings_at(std::int64_t address, std::vector<model::StringRow>& out) const;
    // Windowed string read. end_address is INCLUSIVE (the read_comments_in_range
    // convention) and the result contains every string whose covered byte span
    // (string_byte_span) INTERSECTS [start_address, end_address] — not just
    // strings that START inside it, so a window landing mid-string still sees
    // its covering item. Default falls back to filtering the bulk read, so
    // fixture/callback sources keep working unchanged.
    virtual bool read_strings_in_range(
        std::int64_t start_address,
        std::int64_t end_address,
        std::vector<model::StringRow>& out) const;
    // Raw memory bytes at [address, address+length). Used by the memory_bytes
    // derivation so string bytes reflect the ACTUAL memory (survives a byte
    // patch to a non-ASCII value) instead of the UTF-8-transcoded string
    // content. Default returns false (unsupported) so derivations fall back.
    virtual bool read_bytes(std::int64_t address, std::int64_t length,
                            std::vector<std::uint8_t>& out) const;
    virtual bool read_xrefs(std::vector<model::XrefRow>& out) const;
    virtual bool read_function_calls(std::vector<model::FunctionCallRow>& out) const;
    virtual bool read_call_edges(std::vector<model::CallEdgeRow>& out) const;
    virtual bool read_memory_blocks(std::vector<model::MemoryBlockRow>& out) const;
    virtual bool read_data_items(std::vector<model::DataItemRow>& out) const;
    virtual bool read_data_items_at(std::int64_t address, std::vector<model::DataItemRow>& out) const;
    // Windowed data-item read; end_address INCLUSIVE, span-intersection
    // semantics (see read_strings_in_range).
    virtual bool read_data_items_in_range(
        std::int64_t start_address,
        std::int64_t end_address,
        std::vector<model::DataItemRow>& out) const;
    virtual bool read_blocks(std::vector<model::BlockRow>& out) const;
    virtual bool read_cfg_edges(std::vector<model::CfgEdgeRow>& out) const;
    virtual bool read_switch_tables(std::vector<model::SwitchTableRow>& out) const;
    virtual bool read_dominators(std::vector<model::DominatorRow>& out) const;
    virtual bool read_post_dominators(std::vector<model::PostDominatorRow>& out) const;
    virtual bool read_loops(std::vector<model::LoopRow>& out) const;
    // Decompiler-free stack-frame layout (listing-layer StackFrame). Defaults to
    // false so sources without a StackFrame path fall back to derivation.
    virtual bool read_stack_frames(std::vector<model::FunctionFrameRow>& out) const;
    virtual bool read_stack_frames_in_range(
        std::int64_t start_address,
        std::int64_t end_address,
        std::vector<model::FunctionFrameRow>& out) const;
    // Decompiler-free stack variables (embedded in each frame's StackFrame).
    virtual bool read_stack_vars(std::vector<model::StackVarRow>& out) const;
    virtual bool read_stack_vars_in_range(
        std::int64_t start_address,
        std::int64_t end_address,
        std::vector<model::StackVarRow>& out) const;
    virtual bool read_function_params(std::vector<model::FunctionParamRow>& out) const;
    virtual bool read_instructions(std::vector<model::InstructionRow>& out) const;
    virtual bool read_instruction_at(std::int64_t address, model::InstructionRow& out) const;
    // Windowed instruction read; end_address INCLUSIVE, span-intersection
    // semantics (see read_strings_in_range).
    virtual bool read_instructions_in_range(
        std::int64_t start_address,
        std::int64_t end_address,
        std::vector<model::InstructionRow>& out) const;
    virtual bool read_instruction_operands(std::vector<model::InstructionOperandRow>& out) const;
    // Windowed operand read; end_address INCLUSIVE (see read_instructions_in_range).
    virtual bool read_instruction_operands_in_range(
        std::int64_t start_address,
        std::int64_t end_address,
        std::vector<model::InstructionOperandRow>& out) const;
    virtual bool read_comments(std::vector<model::CommentRow>& out) const;
    virtual bool read_comments_at(std::int64_t address, std::vector<model::CommentRow>& out) const;
    virtual bool read_comments_in_range(
        std::int64_t start_address,
        std::int64_t end_address,
        std::vector<model::CommentRow>& out) const;
    virtual bool read_types(std::vector<model::TypeRow>& out) const;
    virtual bool read_type_members(std::vector<model::TypeMemberRow>& out) const;
    virtual bool read_type_enums(std::vector<model::TypeEnumRow>& out) const;
    virtual bool read_type_enum_members(std::vector<model::TypeEnumMemberRow>& out) const;
    virtual bool read_type_unions(std::vector<model::TypeUnionRow>& out) const;
    virtual bool read_type_aliases(std::vector<model::TypeAliasRow>& out) const;
    virtual bool read_signatures(std::vector<model::SignatureRow>& out) const;
    virtual bool read_breakpoints(std::vector<model::BreakpointRow>& out) const;
    virtual bool read_breakpoints_at(std::int64_t address, std::vector<model::BreakpointRow>& out) const;
    virtual bool read_bookmarks(std::vector<model::BookmarkRow>& out) const;
    virtual bool read_bookmarks_at(std::int64_t address, std::vector<model::BookmarkRow>& out) const;
    virtual bool read_function_tags(std::vector<model::FunctionTagRow>& out) const;
    virtual bool read_function_tag_mappings(std::vector<model::FunctionTagMappingRow>& out) const;
    virtual bool read_program_info(model::ProgramInfoRow& out) const;
    virtual bool read_freshness_token(SourceFreshnessToken& out) const;
    virtual bool read_program_revision(std::int64_t& out) const;
    virtual bool read_pseudocode(std::vector<model::PseudocodeRow>& out) const;
    // Per-function P-code at the requested maturity (High=refined SSA, Raw=per-instruction).
    // Default returns false (no P-code surface).
    virtual bool read_pcode_at(std::int64_t address, model::PcodeMaturity maturity,
                               std::vector<model::PcodeOpRow>& out) const;
    // Per-function P-code value operands (varnodes) at the requested maturity.
    virtual bool read_pcode_varnodes_at(std::int64_t address, model::PcodeMaturity maturity,
                                        std::vector<model::PcodeVarnodeRow>& out) const;
    virtual bool read_decomp_lvars(std::vector<model::DecompLvarRow>& out) const;
    virtual bool read_decomp_comments(std::vector<model::DecompCommentRow>& out) const;
    virtual bool read_decomp_tokens(std::vector<model::DecompTokenRow>& out) const;
    virtual bool read_capabilities(std::vector<model::CapabilityRow>& out) const;
    virtual bool read_parity_findings(std::vector<model::ParityFindingRow>& out) const;
    virtual bool read_perf_benchmarks(std::vector<model::PerfBenchmarkRow>& out) const;
    virtual bool read_live_meta(std::vector<model::LiveMetaRow>& out) const;

    // Optional write callbacks.
    virtual bool rename_function(std::int64_t address, const std::string& new_name);
    virtual bool rename_symbol(std::int64_t address, const std::string& new_name);
    virtual bool delete_symbol(std::int64_t address, const std::string& name);
    virtual bool rename_data_item(std::int64_t address, const std::string& new_name);
    virtual bool set_data_item_type(std::int64_t address, const std::string& new_type);
    virtual bool delete_data_item(std::int64_t address);
    virtual bool set_comment(std::int64_t address, const std::string& comment, bool repeatable);
    virtual bool delete_comment(std::int64_t address, bool repeatable);
    virtual bool set_comment_by_kind(std::int64_t address, const std::string& comment, const std::string& kind);
    virtual bool delete_comment_by_kind(std::int64_t address, const std::string& kind);
    virtual bool rename_decomp_local(
        std::int64_t func_addr,
        const std::string& local_id,
        const std::string& new_name);
    virtual bool set_decomp_local_type(
        std::int64_t func_addr,
        const std::string& local_id,
        const std::string& new_type);
    virtual bool rename_function_param(
        std::int64_t func_addr,
        std::int64_t ordinal,
        const std::string& new_name);
    virtual bool set_function_param_type(
        std::int64_t func_addr,
        std::int64_t ordinal,
        const std::string& new_type);
    virtual bool add_breakpoint(
        std::int64_t address,
        int type,
        std::int64_t size,
        const std::string& condition,
        const std::string& group);
    virtual bool set_breakpoint_enabled(std::int64_t address, bool enabled);
    virtual bool set_breakpoint_type(std::int64_t address, int type);
    virtual bool set_breakpoint_size(std::int64_t address, std::int64_t size);
    virtual bool set_breakpoint_condition(std::int64_t address, const std::string& condition);
    virtual bool set_breakpoint_group(std::int64_t address, const std::string& group);
    virtual bool delete_breakpoint(std::int64_t address);
    virtual bool add_bookmark(
        std::int64_t address,
        const std::string& type,
        const std::string& category,
        const std::string& comment);
    virtual bool set_bookmark_type(
        std::int64_t address,
        const std::string& old_type,
        const std::string& old_category,
        const std::string& new_type);
    virtual bool set_bookmark_category(
        std::int64_t address,
        const std::string& type,
        const std::string& old_category,
        const std::string& new_category);
    virtual bool set_bookmark_comment(
        std::int64_t address,
        const std::string& type,
        const std::string& category,
        const std::string& comment);
    virtual bool delete_bookmark(
        std::int64_t address,
        const std::string& type,
        const std::string& category);
    virtual bool add_perf_benchmark(const model::PerfBenchmarkRow& row);
    virtual bool delete_perf_benchmark(const std::string& bench_id);
    virtual bool create_function_tag(
        const std::string& name,
        const std::string& comment);
    virtual bool delete_function_tag(const std::string& name);
    virtual bool tag_function(
        std::int64_t func_addr,
        const std::string& tag_name);
    virtual bool untag_function(
        std::int64_t func_addr,
        const std::string& tag_name);
    virtual bool rename_type(const std::string& type_id, const std::string& new_name);
    virtual bool create_type(
        const std::string& name,
        const std::string& kind,
        std::int64_t size,
        const std::string& declaration);
    virtual bool delete_type(const std::string& type_id);
    virtual bool create_type_alias(
        const std::string& name,
        const std::string& target_type);
    virtual bool delete_type_alias(const std::string& type_id);
    virtual bool set_type_alias_target(
        const std::string& type_id,
        const std::string& target_type);
    virtual bool create_type_enum(
        const std::string& name,
        std::int64_t width,
        bool is_signed);
    virtual bool delete_type_enum(const std::string& type_id);
    virtual bool add_type_enum_member(
        const std::string& type_id,
        const std::string& name,
        std::int64_t value);
    virtual bool delete_type_enum_member(
        const std::string& type_id,
        std::int64_t ordinal);
    virtual bool rename_type_member(
        const std::string& parent_type_id,
        std::int64_t ordinal,
        const std::string& new_name);
    virtual bool add_type_member(
        const std::string& parent_type_id,
        const std::string& member_name,
        const std::string& member_type,
        std::int64_t size);
    virtual bool delete_type_member(
        const std::string& parent_type_id,
        std::int64_t ordinal);
    virtual bool set_type_member_type(
        const std::string& parent_type_id,
        std::int64_t ordinal,
        const std::string& new_type);
    virtual bool set_type_member_comment(
        const std::string& parent_type_id,
        std::int64_t ordinal,
        const std::string& comment);
    virtual bool rename_type_enum_member(
        const std::string& type_id,
        std::int64_t ordinal,
        const std::string& new_name);
    virtual bool set_type_enum_member_value(
        const std::string& type_id,
        std::int64_t ordinal,
        std::int64_t new_value);
    virtual bool set_type_enum_member_comment(
        const std::string& type_id,
        std::int64_t ordinal,
        const std::string& comment);
    virtual bool create_type_union(
        const std::string& name,
        std::int64_t size,
        const std::string& declaration);
    virtual bool delete_type_union(const std::string& type_id);
    virtual bool set_function_signature(
        std::int64_t owner_addr,
        const std::string& prototype);
    virtual bool create_symbol(std::int64_t address, const std::string& name);
    virtual bool create_data_item(std::int64_t address, const std::string& data_type, const std::string& name);
    virtual bool write_byte(std::int64_t address, std::uint8_t value);
    // Writable memory map (segments / memory_blocks). perm bits: R=4, W=2, X=1.
    virtual bool create_memory_block(std::int64_t start_address, std::int64_t end_address,
                                     const std::string& name, int perm, bool initialized);
    virtual bool remove_memory_block(std::int64_t address);
    virtual bool move_memory_block(std::int64_t address, std::int64_t new_start_address);
    virtual bool save_database();
    virtual bool discard_changes();
    virtual bool refresh();

    // Bulk type import.
    virtual int parse_declarations(const std::string& source_text);

    // Optional analysis callbacks.
    virtual std::string decompile(std::int64_t address) const;
    virtual std::optional<model::DecompilationDetail> decompile_detail(std::int64_t address) const;
    virtual bool has_authoritative_decompile_detail() const;
};

}  // namespace ghidrasql
