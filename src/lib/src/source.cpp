// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <ghidrasql/source.hpp>

#include <algorithm>
#include <limits>

namespace ghidrasql {
namespace {

template <typename Row>
bool clear_and_fail(std::vector<Row>& out) {
    out.clear();
    return false;
}

// Body end of a function: prefer end_ea when it is past the start; otherwise
// derive it from size (clamped to at least 1 byte so a zero-size function still
// covers its own start address).
inline std::int64_t function_body_end(const model::FunctionRow& fn) {
    return fn.end_ea > fn.address
        ? fn.end_ea
        : fn.address + std::max<std::int64_t>(fn.size, 1);
}

}  // namespace

std::int64_t containing_func_addr(
    const std::vector<model::FunctionRow>& funcs, std::int64_t addr) {
    std::int64_t best = 0;
    std::int64_t best_start = 0;
    bool found = false;
    for (const auto& fn : funcs) {
        if (addr >= fn.address && addr < function_body_end(fn)) {
            // On overlap, prefer the function with the greatest start <= addr
            // (innermost / most specific), matching getFunctionContaining.
            if (!found || fn.address > best_start) {
                best = fn.address;
                best_start = fn.address;
                found = true;
            }
        }
    }
    return found ? best : 0;
}

void assign_instruction_func_addrs(
    const std::vector<model::FunctionRow>& funcs,
    std::vector<model::InstructionRow>& instructions) {
    if (instructions.empty()) {
        return;
    }
    // Build a sorted (start, end, func_addr) index once, then binary-search each
    // instruction: the candidate is the last function whose start <= addr.
    struct FuncSpan {
        std::int64_t start;
        std::int64_t end;
    };
    std::vector<FuncSpan> spans;
    spans.reserve(funcs.size());
    for (const auto& fn : funcs) {
        spans.push_back({fn.address, function_body_end(fn)});
    }
    std::sort(spans.begin(), spans.end(),
              [](const FuncSpan& a, const FuncSpan& b) { return a.start < b.start; });

    for (auto& insn : instructions) {
        // Assign the SAME function containing_func_addr() would (getFunction
        // Containing semantics): the greatest-start function whose body contains
        // addr. Spans are sorted by start ascending, so every span before the
        // upper_bound has start <= addr; walk backward (decreasing start) and take
        // the first one that also satisfies addr < end. On a non-overlapping layout
        // that is the immediate predecessor (O(1)); under nested/overlapping bodies
        // an earlier span with a larger body may still contain addr, so we keep
        // walking — matching the linear path exactly instead of giving up after the
        // single nearest candidate (which previously disagreed and returned 0).
        insn.func_addr = 0;
        auto it = std::upper_bound(
            spans.begin(), spans.end(), insn.address,
            [](std::int64_t addr, const FuncSpan& s) { return addr < s.start; });
        while (it != spans.begin()) {
            --it;
            if (insn.address < it->end) {  // it->start <= addr already guaranteed
                insn.func_addr = it->start;
                break;
            }
        }
    }
}

void assign_operand_func_addrs(
    const std::vector<model::FunctionRow>& funcs,
    std::vector<model::InstructionOperandRow>& operands) {
    // Same sorted-span getFunctionContaining sweep as assign_instruction_func_addrs,
    // over operand rows (each operand sits at its instruction's address).
    if (operands.empty()) {
        return;
    }
    struct FuncSpan {
        std::int64_t start;
        std::int64_t end;
    };
    std::vector<FuncSpan> spans;
    spans.reserve(funcs.size());
    for (const auto& fn : funcs) {
        spans.push_back({fn.address, function_body_end(fn)});
    }
    std::sort(spans.begin(), spans.end(),
              [](const FuncSpan& a, const FuncSpan& b) { return a.start < b.start; });

    for (auto& op : operands) {
        op.func_addr = 0;
        auto it = std::upper_bound(
            spans.begin(), spans.end(), op.address,
            [](std::int64_t addr, const FuncSpan& s) { return addr < s.start; });
        while (it != spans.begin()) {
            --it;
            if (op.address < it->end) {
                op.func_addr = it->start;
                break;
            }
        }
    }
}

namespace {

// Count of full hex-digit pairs at the front of an instruction's `bytes` hex
// string (the decodable byte prefix). Stops at the first non-hex character.
std::int64_t decoded_hex_byte_count(const std::string& hex) {
    auto is_hex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    };
    std::int64_t count = 0;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        if (!is_hex(hex[i]) || !is_hex(hex[i + 1])) {
            break;
        }
        ++count;
    }
    return count;
}

}  // namespace

std::int64_t instruction_byte_span(const model::InstructionRow& row) {
    const std::int64_t decoded = decoded_hex_byte_count(row.bytes);
    const std::int64_t span = std::max<std::int64_t>(row.size, decoded);
    return std::max<std::int64_t>(span, 1);
}

std::int64_t string_byte_span(const model::StringRow& row) {
    const std::int64_t span =
        row.length > 0 ? row.length : static_cast<std::int64_t>(row.content.size());
    return std::max<std::int64_t>(span, 1);
}

std::int64_t data_item_byte_span(const model::DataItemRow& row) {
    return std::max<std::int64_t>(row.size, 1);
}

bool byte_span_intersects_range(
    std::int64_t item_start,
    std::int64_t span,
    std::int64_t start_address,
    std::int64_t end_address) {
    if (span <= 0 || end_address < start_address) {
        return false;
    }
    // Inclusive item end, clamped on overflow (a span reaching past INT64_MAX
    // saturates rather than wrapping). Computed in unsigned arithmetic so the
    // overflow itself is well-defined.
    std::int64_t item_end = static_cast<std::int64_t>(
        static_cast<std::uint64_t>(item_start) + static_cast<std::uint64_t>(span - 1));
    if (item_end < item_start) {
        item_end = std::numeric_limits<std::int64_t>::max();
    }
    return item_start <= end_address && item_end >= start_address;
}

std::string Source::last_error() const { return {}; }

bool Source::read_project_files(std::vector<model::ProjectFileRow>& out) const { return clear_and_fail(out); }
bool Source::read_functions(std::vector<model::FunctionRow>& out) const { return clear_and_fail(out); }
bool Source::read_function_at(std::int64_t address, model::FunctionRow& out) const {
    std::vector<model::FunctionRow> all;
    if (!read_functions(all)) {
        out = {};
        return false;
    }
    for (const auto& row : all) {
        if (row.address == address) {
            out = row;
            return true;
        }
    }
    out = {};
    return false;
}
bool Source::read_segments(std::vector<model::SegmentRow>& out) const { return clear_and_fail(out); }
bool Source::read_symbols(std::vector<model::SymbolRow>& out) const { return clear_and_fail(out); }
bool Source::read_symbols_at(std::int64_t address, std::vector<model::SymbolRow>& out) const {
    std::vector<model::SymbolRow> all;
    if (!read_symbols(all)) { out.clear(); return false; }
    out.clear();
    for (auto& row : all) {
        if (row.address == address) out.push_back(std::move(row));
    }
    return true;
}
bool Source::read_imports(std::vector<model::ImportRow>& out) const { return clear_and_fail(out); }
bool Source::read_exports(std::vector<model::ExportRow>& out) const { return clear_and_fail(out); }
bool Source::read_strings(std::vector<model::StringRow>& out) const { return clear_and_fail(out); }
bool Source::read_strings_at(std::int64_t address, std::vector<model::StringRow>& out) const {
    std::vector<model::StringRow> all;
    if (!read_strings(all)) { out.clear(); return false; }
    out.clear();
    for (auto& row : all) {
        if (row.address == address) out.push_back(std::move(row));
    }
    return true;
}
bool Source::read_strings_in_range(
    std::int64_t start_address,
    std::int64_t end_address,
    std::vector<model::StringRow>& out) const {
    // Default: filter the bulk read by covered-span intersection (end is
    // INCLUSIVE — the read_comments_in_range convention).
    std::vector<model::StringRow> all;
    if (!read_strings(all)) { out.clear(); return false; }
    out.clear();
    for (auto& s : all) {
        if (byte_span_intersects_range(s.address, string_byte_span(s), start_address, end_address)) {
            out.push_back(std::move(s));
        }
    }
    return true;
}
bool Source::read_bytes(std::int64_t, std::int64_t, std::vector<std::uint8_t>& out) const {
    out.clear();
    return false;
}
bool Source::read_xrefs(std::vector<model::XrefRow>& out) const { return clear_and_fail(out); }
bool Source::read_function_calls(std::vector<model::FunctionCallRow>& out) const { return clear_and_fail(out); }
bool Source::read_call_edges(std::vector<model::CallEdgeRow>& out) const { return clear_and_fail(out); }
bool Source::read_memory_blocks(std::vector<model::MemoryBlockRow>& out) const { return clear_and_fail(out); }
bool Source::read_data_items(std::vector<model::DataItemRow>& out) const { return clear_and_fail(out); }
bool Source::read_data_items_at(std::int64_t address, std::vector<model::DataItemRow>& out) const {
    std::vector<model::DataItemRow> all;
    if (!read_data_items(all)) { out.clear(); return false; }
    out.clear();
    for (auto& row : all) {
        if (row.address == address) out.push_back(std::move(row));
    }
    return true;
}
bool Source::read_data_items_in_range(
    std::int64_t start_address,
    std::int64_t end_address,
    std::vector<model::DataItemRow>& out) const {
    // Default: filter the bulk read by covered-span intersection (end is
    // INCLUSIVE — the read_comments_in_range convention).
    std::vector<model::DataItemRow> all;
    if (!read_data_items(all)) { out.clear(); return false; }
    out.clear();
    for (auto& di : all) {
        if (byte_span_intersects_range(di.address, data_item_byte_span(di), start_address, end_address)) {
            out.push_back(std::move(di));
        }
    }
    return true;
}
bool Source::read_blocks(std::vector<model::BlockRow>& out) const { return clear_and_fail(out); }
bool Source::read_cfg_edges(std::vector<model::CfgEdgeRow>& out) const { return clear_and_fail(out); }
bool Source::read_switch_tables(std::vector<model::SwitchTableRow>& out) const { return clear_and_fail(out); }
bool Source::read_dominators(std::vector<model::DominatorRow>& out) const { return clear_and_fail(out); }
bool Source::read_post_dominators(std::vector<model::PostDominatorRow>& out) const { return clear_and_fail(out); }
bool Source::read_loops(std::vector<model::LoopRow>& out) const { return clear_and_fail(out); }
bool Source::read_stack_frames(std::vector<model::FunctionFrameRow>& out) const { return clear_and_fail(out); }
bool Source::read_stack_frames_in_range(
    std::int64_t start_address,
    std::int64_t end_address,
    std::vector<model::FunctionFrameRow>& out) const {
    std::vector<model::FunctionFrameRow> all;
    if (!read_stack_frames(all)) { out.clear(); return false; }
    out.clear();
    for (auto& r : all) {
        if (r.func_addr >= start_address && r.func_addr <= end_address) {
            out.push_back(std::move(r));
        }
    }
    return true;
}
bool Source::read_stack_vars(std::vector<model::StackVarRow>& out) const { return clear_and_fail(out); }
bool Source::read_stack_vars_in_range(
    std::int64_t start_address,
    std::int64_t end_address,
    std::vector<model::StackVarRow>& out) const {
    std::vector<model::StackVarRow> all;
    if (!read_stack_vars(all)) { out.clear(); return false; }
    out.clear();
    for (auto& r : all) {
        if (r.func_addr >= start_address && r.func_addr <= end_address) {
            out.push_back(std::move(r));
        }
    }
    return true;
}
bool Source::read_function_params(std::vector<model::FunctionParamRow>& out) const { return clear_and_fail(out); }
bool Source::read_instructions(std::vector<model::InstructionRow>& out) const { return clear_and_fail(out); }
bool Source::read_instruction_at(std::int64_t address, model::InstructionRow& out) const {
    std::vector<model::InstructionRow> all;
    if (!read_instructions(all)) {
        out = {};
        return false;
    }
    for (const auto& row : all) {
        if (row.address == address) {
            out = row;
            return true;
        }
    }
    out = {};
    return false;
}
bool Source::read_instructions_in_range(
    std::int64_t start_address,
    std::int64_t end_address,
    std::vector<model::InstructionRow>& out) const {
    // Default: filter the bulk read by covered-span intersection (end is
    // INCLUSIVE — the read_comments_in_range convention).
    std::vector<model::InstructionRow> all;
    if (!read_instructions(all)) { out.clear(); return false; }
    out.clear();
    for (auto& insn : all) {
        if (byte_span_intersects_range(
                insn.address, instruction_byte_span(insn), start_address, end_address)) {
            out.push_back(std::move(insn));
        }
    }
    return true;
}
bool Source::read_instruction_operands(std::vector<model::InstructionOperandRow>& out) const { return clear_and_fail(out); }
bool Source::read_instruction_operands_in_range(
    std::int64_t start_address,
    std::int64_t end_address,
    std::vector<model::InstructionOperandRow>& out) const {
    // Default: filter the bulk read by instruction address (end INCLUSIVE). An
    // operand sits at a single instruction address, so a point read (start==end)
    // returns just that instruction's operands.
    std::vector<model::InstructionOperandRow> all;
    if (!read_instruction_operands(all)) { out.clear(); return false; }
    out.clear();
    for (auto& op : all) {
        if (op.address >= start_address && op.address <= end_address) {
            out.push_back(std::move(op));
        }
    }
    return true;
}
bool Source::read_comments(std::vector<model::CommentRow>& out) const { return clear_and_fail(out); }
bool Source::read_comments_at(std::int64_t address, std::vector<model::CommentRow>& out) const {
    // Default: fall back to bulk read + filter.
    std::vector<model::CommentRow> all;
    if (!read_comments(all)) { out.clear(); return false; }
    out.clear();
    for (auto& c : all) {
        if (c.address == address) out.push_back(std::move(c));
    }
    return true;
}
bool Source::read_comments_in_range(
    std::int64_t start_address,
    std::int64_t end_address,
    std::vector<model::CommentRow>& out) const {
    std::vector<model::CommentRow> all;
    if (!read_comments(all)) { out.clear(); return false; }
    out.clear();
    for (auto& c : all) {
        if (c.address >= start_address && c.address <= end_address) {
            out.push_back(std::move(c));
        }
    }
    return true;
}
bool Source::read_types(std::vector<model::TypeRow>& out) const { return clear_and_fail(out); }
bool Source::read_type_members(std::vector<model::TypeMemberRow>& out) const { return clear_and_fail(out); }
bool Source::read_type_enums(std::vector<model::TypeEnumRow>& out) const { return clear_and_fail(out); }
bool Source::read_type_enum_members(std::vector<model::TypeEnumMemberRow>& out) const { return clear_and_fail(out); }
bool Source::read_type_unions(std::vector<model::TypeUnionRow>& out) const { return clear_and_fail(out); }
bool Source::read_type_aliases(std::vector<model::TypeAliasRow>& out) const { return clear_and_fail(out); }
bool Source::read_signatures(std::vector<model::SignatureRow>& out) const { return clear_and_fail(out); }
bool Source::read_breakpoints(std::vector<model::BreakpointRow>& out) const { return clear_and_fail(out); }
bool Source::read_breakpoints_at(std::int64_t address, std::vector<model::BreakpointRow>& out) const {
    std::vector<model::BreakpointRow> all;
    if (!read_breakpoints(all)) { out.clear(); return false; }
    out.clear();
    for (auto& row : all) {
        if (row.address == address) out.push_back(std::move(row));
    }
    return true;
}
bool Source::read_bookmarks(std::vector<model::BookmarkRow>& out) const { return clear_and_fail(out); }
bool Source::read_bookmarks_at(std::int64_t address, std::vector<model::BookmarkRow>& out) const {
    std::vector<model::BookmarkRow> all;
    if (!read_bookmarks(all)) { out.clear(); return false; }
    out.clear();
    for (auto& row : all) {
        if (row.address == address) out.push_back(std::move(row));
    }
    return true;
}
bool Source::read_function_tags(std::vector<model::FunctionTagRow>& out) const { return clear_and_fail(out); }
bool Source::read_function_tag_mappings(std::vector<model::FunctionTagMappingRow>& out) const { return clear_and_fail(out); }
bool Source::read_program_info(model::ProgramInfoRow& out) const {
    out = {};
    return false;
}
bool Source::read_freshness_token(SourceFreshnessToken& out) const {
    out = {};
    return false;
}
bool Source::read_program_revision(std::int64_t& out) const {
    out = 0;
    return false;
}
bool Source::read_pseudocode(std::vector<model::PseudocodeRow>& out) const { return clear_and_fail(out); }
bool Source::read_pcode_at(std::int64_t address, model::PcodeMaturity maturity, std::vector<model::PcodeOpRow>& out) const { (void)address; (void)maturity; return clear_and_fail(out); }
bool Source::read_pcode_varnodes_at(std::int64_t address, model::PcodeMaturity maturity, std::vector<model::PcodeVarnodeRow>& out) const { (void)address; (void)maturity; return clear_and_fail(out); }
bool Source::read_decomp_lvars(std::vector<model::DecompLvarRow>& out) const { return clear_and_fail(out); }
bool Source::read_decomp_comments(std::vector<model::DecompCommentRow>& out) const { return clear_and_fail(out); }
bool Source::read_decomp_tokens(std::vector<model::DecompTokenRow>& out) const { return clear_and_fail(out); }
bool Source::read_capabilities(std::vector<model::CapabilityRow>& out) const { return clear_and_fail(out); }
bool Source::read_parity_findings(std::vector<model::ParityFindingRow>& out) const { return clear_and_fail(out); }
bool Source::read_perf_benchmarks(std::vector<model::PerfBenchmarkRow>& out) const { return clear_and_fail(out); }
bool Source::read_live_meta(std::vector<model::LiveMetaRow>& out) const { return clear_and_fail(out); }

bool Source::rename_function(std::int64_t, const std::string&) { return false; }
bool Source::rename_symbol(std::int64_t, const std::string&) { return false; }
bool Source::delete_symbol(std::int64_t, const std::string&) { return false; }
bool Source::rename_data_item(std::int64_t, const std::string&) { return false; }
bool Source::set_data_item_type(std::int64_t, const std::string&) { return false; }
bool Source::delete_data_item(std::int64_t) { return false; }
bool Source::set_comment(std::int64_t, const std::string&, bool) { return false; }
bool Source::delete_comment(std::int64_t, bool) { return false; }
bool Source::set_comment_by_kind(std::int64_t, const std::string&, const std::string&) { return false; }
bool Source::delete_comment_by_kind(std::int64_t, const std::string&) { return false; }
bool Source::rename_decomp_local(std::int64_t, const std::string&, const std::string&) { return false; }
bool Source::set_decomp_local_type(std::int64_t, const std::string&, const std::string&) { return false; }
bool Source::rename_function_param(std::int64_t, std::int64_t, const std::string&) { return false; }
bool Source::set_function_param_type(std::int64_t, std::int64_t, const std::string&) { return false; }
bool Source::add_breakpoint(std::int64_t, int, std::int64_t, const std::string&, const std::string&) { return false; }
bool Source::set_breakpoint_enabled(std::int64_t, bool) { return false; }
bool Source::set_breakpoint_type(std::int64_t, int) { return false; }
bool Source::set_breakpoint_size(std::int64_t, std::int64_t) { return false; }
bool Source::set_breakpoint_condition(std::int64_t, const std::string&) { return false; }
bool Source::set_breakpoint_group(std::int64_t, const std::string&) { return false; }
bool Source::delete_breakpoint(std::int64_t) { return false; }
bool Source::add_bookmark(std::int64_t, const std::string&, const std::string&, const std::string&) { return false; }
bool Source::set_bookmark_type(std::int64_t, const std::string&, const std::string&, const std::string&) { return false; }
bool Source::set_bookmark_category(std::int64_t, const std::string&, const std::string&, const std::string&) {
    return false;
}
bool Source::set_bookmark_comment(std::int64_t, const std::string&, const std::string&, const std::string&) {
    return false;
}
bool Source::delete_bookmark(std::int64_t, const std::string&, const std::string&) { return false; }
bool Source::add_perf_benchmark(const model::PerfBenchmarkRow&) { return false; }
bool Source::delete_perf_benchmark(const std::string&) { return false; }
bool Source::create_function_tag(const std::string&, const std::string&) { return false; }
bool Source::delete_function_tag(const std::string&) { return false; }
bool Source::tag_function(std::int64_t, const std::string&) { return false; }
bool Source::untag_function(std::int64_t, const std::string&) { return false; }
bool Source::rename_type(const std::string&, const std::string&) { return false; }
bool Source::create_type(const std::string&, const std::string&, std::int64_t, const std::string&) { return false; }
bool Source::delete_type(const std::string&) { return false; }
bool Source::create_type_alias(const std::string&, const std::string&) { return false; }
bool Source::delete_type_alias(const std::string&) { return false; }
bool Source::set_type_alias_target(const std::string&, const std::string&) { return false; }
bool Source::create_type_enum(const std::string&, std::int64_t, bool) { return false; }
bool Source::delete_type_enum(const std::string&) { return false; }
bool Source::add_type_enum_member(const std::string&, const std::string&, std::int64_t) { return false; }
bool Source::delete_type_enum_member(const std::string&, std::int64_t) { return false; }
bool Source::rename_type_member(const std::string&, std::int64_t, const std::string&) { return false; }
bool Source::add_type_member(const std::string&, const std::string&, const std::string&, std::int64_t) { return false; }
bool Source::delete_type_member(const std::string&, std::int64_t) { return false; }
bool Source::set_type_member_type(const std::string&, std::int64_t, const std::string&) { return false; }
bool Source::set_type_member_comment(const std::string&, std::int64_t, const std::string&) { return false; }
bool Source::rename_type_enum_member(const std::string&, std::int64_t, const std::string&) { return false; }
bool Source::set_type_enum_member_value(const std::string&, std::int64_t, std::int64_t) { return false; }
bool Source::set_type_enum_member_comment(const std::string&, std::int64_t, const std::string&) { return false; }
bool Source::create_type_union(const std::string&, std::int64_t, const std::string&) { return false; }
bool Source::delete_type_union(const std::string&) { return false; }
bool Source::set_function_signature(std::int64_t, const std::string&) { return false; }
bool Source::create_symbol(std::int64_t, const std::string&) { return false; }
bool Source::create_data_item(std::int64_t, const std::string&, const std::string&) { return false; }
bool Source::write_byte(std::int64_t, std::uint8_t) { return false; }
bool Source::create_memory_block(std::int64_t, std::int64_t, const std::string&, int, bool) { return false; }
bool Source::remove_memory_block(std::int64_t) { return false; }
bool Source::move_memory_block(std::int64_t, std::int64_t) { return false; }
bool Source::save_database() { return false; }
bool Source::discard_changes() { return false; }
bool Source::refresh() { return false; }
int Source::parse_declarations(const std::string&) { return -1; }

std::string Source::decompile(std::int64_t) const { return {}; }

std::optional<model::DecompilationDetail> Source::decompile_detail(std::int64_t address) const {
    std::vector<model::PseudocodeRow> pseudocode_rows;
    const bool has_pseudocode_rows = read_pseudocode(pseudocode_rows);
    const auto pseudo_it = has_pseudocode_rows
        ? std::find_if(
              pseudocode_rows.begin(),
              pseudocode_rows.end(),
              [address](const model::PseudocodeRow& row) { return row.func_addr == address; })
        : pseudocode_rows.end();

    std::string text = decompile(address);
    if (text.empty() && pseudo_it != pseudocode_rows.end()) {
        text = pseudo_it->text;
    }
    if (text.empty()) {
        return std::nullopt;
    }
    model::DecompilationDetail detail;
    detail.func_addr = address;
    detail.pseudocode = text;
    detail.completed = true;
    if (pseudo_it != pseudocode_rows.end()) {
        detail.func_name = pseudo_it->func_name;
    }

    model::FunctionRow function;
    if (read_function_at(address, function)) {
        detail.func_name = function.name;
        detail.prototype = function.signature;
    }

    std::vector<model::DecompLvarRow> locals;
    if (read_decomp_lvars(locals)) {
        for (const auto& local : locals) {
            if (local.func_addr == address) {
                auto mapped = local;
                if (mapped.func_name.empty()) {
                    mapped.func_name = detail.func_name;
                }
                detail.locals.push_back(std::move(mapped));
            }
        }
    }

    std::vector<model::DecompTokenRow> tokens;
    if (read_decomp_tokens(tokens)) {
        for (const auto& token : tokens) {
            if (token.func_addr == address) {
                detail.tokens.push_back(token);
            }
        }
    }

    return detail;
}

bool Source::has_authoritative_decompile_detail() const {
    return false;
}

}  // namespace ghidrasql
