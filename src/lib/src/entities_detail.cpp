// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "internal/entities_detail.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ghidrasql::entities {

namespace {

std::optional<model::FunctionRow> read_function_row_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr)
{
    model::FunctionRow function;
    if (!source->read_function_at(func_addr, function)) {
        return std::nullopt;
    }
    return function;
}

std::vector<model::DecompLvarRow> read_source_decomp_lvar_rows_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr)
{
    std::vector<model::DecompLvarRow> source_rows;
    if (!source->read_decomp_lvars(source_rows) || source_rows.empty()) {
        return {};
    }
    std::vector<model::DecompLvarRow> out;
    out.reserve(source_rows.size());
    for (const auto& row : source_rows) {
        if (row.func_addr == func_addr) {
            out.push_back(row);
        }
    }
    return out;
}

std::vector<model::DecompLvarRow> merge_decomp_lvar_rows(
    std::vector<model::DecompLvarRow> primary,
    const std::vector<model::DecompLvarRow>& fallback)
{
    std::unordered_set<std::string> seen_ids;
    seen_ids.reserve(primary.size());
    for (const auto& row : primary) {
        seen_ids.insert(row.local_id);
    }
    for (const auto& row : fallback) {
        if (seen_ids.insert(row.local_id).second) {
            primary.push_back(row);
        }
    }
    return primary;
}

}  // namespace

std::string build_row_counts_json(const std::shared_ptr<Source>& source) {
    std::vector<model::ProjectFileRow> project_files;
    std::vector<model::FunctionRow> funcs;
    std::vector<model::SegmentRow> segments;
    std::vector<model::MemoryBlockRow> memory_blocks;
    std::vector<model::SymbolRow> names;
    std::vector<model::ImportRow> imports;
    std::vector<model::ExportRow> exports;
    std::vector<model::StringRow> strings;
    std::vector<model::XrefRow> xrefs;
    std::vector<model::CallEdgeRow> call_edges;
    std::vector<model::FunctionCallRow> function_calls;
    std::vector<model::BlockRow> blocks;
    std::vector<model::CfgEdgeRow> cfg_edges;
    std::vector<model::InstructionRow> instructions;
    std::vector<model::CommentRow> comments;
    std::vector<model::DataItemRow> data_items;
    std::vector<model::FunctionParamRow> function_params;
    std::vector<model::BreakpointRow> breakpoints;
    std::vector<model::BookmarkRow> bookmarks;
    std::vector<model::PseudocodeRow> pseudocode;
    std::vector<model::DecompLvarRow> decomp_lvars;
    std::vector<model::DecompCommentRow> decomp_comments;
    std::vector<model::DecompTokenRow> decomp_tokens;
    std::vector<model::SwitchTableRow> switch_tables;
    std::vector<model::DominatorRow> dominators;
    std::vector<model::PostDominatorRow> post_dominators;
    std::vector<model::LoopRow> loops;
    std::vector<model::CapabilityRow> sql_capabilities;
    std::vector<model::ParityFindingRow> parity_findings;
    std::vector<model::PerfBenchmarkRow> perf_benchmarks;

    source->read_project_files(project_files);
    source->read_functions(funcs);
    source->read_segments(segments);
    source->read_memory_blocks(memory_blocks);
    source->read_symbols(names);
    source->read_imports(imports);
    source->read_exports(exports);
    source->read_strings(strings);
    source->read_xrefs(xrefs);
    source->read_call_edges(call_edges);
    source->read_function_calls(function_calls);
    source->read_blocks(blocks);
    source->read_cfg_edges(cfg_edges);
    source->read_function_params(function_params);
    source->read_instructions(instructions);
    source->read_comments(comments);
    source->read_data_items(data_items);
    source->read_switch_tables(switch_tables);
    source->read_dominators(dominators);
    source->read_post_dominators(post_dominators);
    source->read_loops(loops);
    source->read_breakpoints(breakpoints);
    source->read_bookmarks(bookmarks);
    source->read_pseudocode(pseudocode);
    source->read_decomp_lvars(decomp_lvars);
    source->read_decomp_comments(decomp_comments);
    source->read_decomp_tokens(decomp_tokens);
    source->read_capabilities(sql_capabilities);
    source->read_parity_findings(parity_findings);
    source->read_perf_benchmarks(perf_benchmarks);

    xsql::json row_counts = {
        {"project_files", project_files.size()},
        {"project_programs", std::count_if(
            project_files.begin(),
            project_files.end(),
            [](const model::ProjectFileRow& row) { return row.is_program != 0; })},
        {"funcs", funcs.size()},
        {"segments", segments.size()},
        {"memory_blocks", memory_blocks.size()},
        {"memory_bytes", 0},
        {"names", names.size()},
        {"imports", imports.size()},
        {"exports", exports.size()},
        {"strings", strings.size()},
        {"xrefs", xrefs.size()},
        {"call_edges", call_edges.size()},
        {"function_calls", function_calls.size()},
        {"blocks", blocks.size()},
        {"cfg_edges", cfg_edges.size()},
        {"loops", loops.size()},
        {"switch_tables", switch_tables.size()},
        {"dominators", dominators.size()},
        {"post_dominators", post_dominators.size()},
        {"instructions", instructions.size()},
        {"comments", comments.size()},
        {"data_items", data_items.size()},
        {"function_locals", 0},
        {"stack_vars", 0},
        {"register_vars", 0},
        {"function_chunks", 0},
        {"tail_calls", 0},
        {"program_options", 0},
        {"analysis_passes", 0},
        {"transactions", 0},
        {"project_properties", 0},
        {"relocations", 0},
        {"constants", 0},
        {"equates", 0},
        {"types", 0},
        {"type_members", 0},
        {"type_enums", 0},
        {"type_enum_members", 0},
        {"type_unions", 0},
        {"type_aliases", 0},
        {"signatures", 0},
        {"function_params", function_params.size()},
        {"function_frames", 0},
        {"text_index", 0},
        {"search_index", 0},
        {"xref_index", 0},
        {"function_metrics", 0},
        {"pseudocode", pseudocode.size()},
        {"decomp_lvars", decomp_lvars.size()},
        {"decomp_comments", decomp_comments.size()},
        {"decomp_tokens", decomp_tokens.size()},
        {"breakpoints", breakpoints.size()},
        {"bookmarks", bookmarks.size()},
        {"sql_capabilities", sql_capabilities.size()},
        {"parity_findings", parity_findings.size()},
        {"perf_benchmarks", perf_benchmarks.size()},
    };
    return row_counts.dump();
}

std::string trim_copy(const std::string& input) {
    size_t begin = 0;
    while (begin < input.size() && std::isspace(static_cast<unsigned char>(input[begin])) != 0) {
        ++begin;
    }
    size_t end = input.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1])) != 0) {
        --end;
    }
    return input.substr(begin, end - begin);
}

std::vector<std::string> split_csv_params(const std::string& params) {
    std::vector<std::string> out;
    std::string cur;
    int depth = 0;
    for (char ch : params) {
        if (ch == '(') {
            ++depth;
            cur.push_back(ch);
            continue;
        }
        if (ch == ')') {
            if (depth > 0) {
                --depth;
            }
            cur.push_back(ch);
            continue;
        }
        if (ch == ',' && depth == 0) {
            const std::string item = trim_copy(cur);
            if (!item.empty()) {
                out.push_back(item);
            }
            cur.clear();
            continue;
        }
        cur.push_back(ch);
    }
    const std::string tail = trim_copy(cur);
    if (!tail.empty()) {
        out.push_back(tail);
    }
    return out;
}

std::string infer_param_name(const std::string& param_decl, size_t idx) {
    size_t end = param_decl.size();
    while (end > 0 && std::isspace(static_cast<unsigned char>(param_decl[end - 1])) != 0) {
        --end;
    }
    size_t begin = end;
    while (begin > 0) {
        const char ch = param_decl[begin - 1];
        const bool ident = std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_';
        if (!ident) {
            break;
        }
        --begin;
    }
    std::string candidate;
    if (begin < end) {
        candidate = param_decl.substr(begin, end - begin);
    }
    if (candidate.empty()) {
        return "arg" + std::to_string(idx);
    }
    static const std::vector<std::string> type_words = {
        "void", "char", "short", "int", "long", "float", "double", "bool",
        "signed", "unsigned", "const", "volatile", "struct", "class", "enum"
    };
    for (const auto& kw : type_words) {
        if (candidate == kw) {
            return "arg" + std::to_string(idx);
        }
    }
    return candidate;
}

std::string lower_copy(std::string text) {
    for (char& ch : text) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return text;
}

std::int64_t stable_type_ordinal(const std::string& type_id) {
    if (type_id.empty()) {
        return 0;
    }
    char* end = nullptr;
    const auto parsed = std::strtoll(type_id.c_str(), &end, 10);
    if (end != nullptr && *end == '\0') {
        return static_cast<std::int64_t>(parsed);
    }

    std::uint64_t hash = 1469598103934665603ull; // FNV-1a 64-bit offset basis.
    for (const unsigned char ch : type_id) {
        hash ^= static_cast<std::uint64_t>(ch);
        hash *= 1099511628211ull; // FNV-1a 64-bit prime.
    }
    const std::int64_t folded = static_cast<std::int64_t>(hash & 0x7fffffffffffffffULL);
    return folded == 0 ? 1 : folded;
}

std::string parse_return_type_from_prototype(const std::string& prototype) {
    const std::string proto = trim_copy(prototype);
    const size_t l = proto.find('(');
    if (l == std::string::npos) {
        return "void";
    }
    const std::string prefix = trim_copy(proto.substr(0, l));
    const size_t sp = prefix.find_last_of(" \t");
    if (sp == std::string::npos) {
        return "void";
    }
    const std::string out = trim_copy(prefix.substr(0, sp));
    return out.empty() ? std::string("void") : out;
}

std::int64_t parse_param_count_from_prototype(const std::string& prototype) {
    const std::string proto = trim_copy(prototype);
    const size_t l = proto.find('(');
    const size_t r = proto.rfind(')');
    if (l == std::string::npos || r == std::string::npos || r <= l + 1) {
        return 0;
    }
    const std::string inside = trim_copy(proto.substr(l + 1, r - l - 1));
    if (inside.empty() || inside == "void") {
        return 0;
    }
    return static_cast<std::int64_t>(split_csv_params(inside).size());
}

std::string function_return_type(const model::FunctionRow& row) {
    if (!row.signature.empty()) {
        return parse_return_type_from_prototype(row.signature);
    }
    return "void";
}

std::int64_t function_arg_count(const model::FunctionRow& row) {
    if (!row.signature.empty()) {
        return parse_param_count_from_prototype(row.signature);
    }
    return 0;
}

std::string function_calling_convention(const model::FunctionRow& row) {
    (void)row;
    return "";
}

std::string normalize_type_token(std::string text) {
    text = lower_copy(text);
    std::string out;
    out.reserve(text.size());
    for (char ch : text) {
        if (std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_' || ch == '*') {
            out.push_back(ch);
        } else if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
            if (!out.empty() && out.back() != ' ') {
                out.push_back(' ');
            }
        }
    }
    if (!out.empty() && out.back() == ' ') {
        out.pop_back();
    }
    return trim_copy(out);
}

bool type_is_pointer_compat(const std::string& type_text) {
    const std::string t = lower_copy(type_text);
    return t.find('*') != std::string::npos || t.find("ptr") != std::string::npos || t.find('&') != std::string::npos;
}

bool type_is_void_compat(const std::string& type_text) {
    const std::string t = normalize_type_token(type_text);
    return t == "void";
}

bool type_is_int_compat(const std::string& type_text) {
    const std::string t = normalize_type_token(type_text);
    static const std::unordered_set<std::string> exact_int = {
        "int",
        "signed int",
        "unsigned int",
        "int32_t",
        "uint32_t",
    };
    return exact_int.find(t) != exact_int.end();
}

bool type_is_integral_compat(const std::string& type_text) {
    const std::string t = normalize_type_token(type_text);
    if (t.empty()) {
        return false;
    }
    static const std::vector<std::string> tokens = {
        "int", "char", "short", "long", "bool",
        "int8", "int16", "int32", "int64",
        "uint8", "uint16", "uint32", "uint64",
        "size_t", "ssize_t", "dword", "word", "byte"
    };
    for (const auto& token : tokens) {
        if (t.find(token) != std::string::npos) {
            return true;
        }
    }
    return false;
}

const char* breakpoint_type_name(int type) {
    switch (type) {
        case 0:
            return "software";
        case 1:
            return "hardware";
        case 2:
            return "read_watch";
        case 3:
            return "access_watch";
        default:
            return "unknown";
    }
}

const char* breakpoint_loc_type_name(int loc_type) {
    switch (loc_type) {
        case 0:
            return "address";
        case 1:
            return "module";
        case 2:
            return "symbol";
        case 3:
            return "source";
        default:
            return "unknown";
    }
}

std::int64_t function_for_address(
    const std::vector<model::FunctionRow>& functions,
    std::int64_t address)
{
    for (const auto& fn : functions) {
        std::int64_t fn_end = fn.end_ea;
        if (fn_end <= fn.address && fn.size > 0) {
            fn_end = fn.address + fn.size;
        }
        if (fn_end <= fn.address) {
            fn_end = fn.address + 1;
        }
        if (address >= fn.address && address < fn_end) {
            return fn.address;
        }
    }
    return 0;
}

std::vector<SegmentRange> build_segment_ranges(const std::vector<model::SegmentRow>& segments) {
    std::vector<SegmentRange> ranges;
    ranges.reserve(segments.size());
    for (const auto& seg : segments) {
        SegmentRange r;
        r.start = seg.start_ea;
        r.end = seg.end_ea;
        r.name = seg.name;
        ranges.push_back(std::move(r));
    }
    std::sort(ranges.begin(), ranges.end(), [](const SegmentRange& a, const SegmentRange& b) {
        return a.start < b.start;
    });
    return ranges;
}

std::string segment_name_for_address(const std::vector<SegmentRange>& ranges, std::int64_t address) {
    if (ranges.empty()) {
        return {};
    }
    auto it = std::upper_bound(
        ranges.begin(),
        ranges.end(),
        address,
        [](std::int64_t value, const SegmentRange& r) {
            return value < r.start;
        });
    if (it == ranges.begin()) {
        return {};
    }
    --it;
    return (address >= it->start && address < it->end) ? it->name : std::string{};
}

std::vector<FunctionRange> build_function_ranges(const std::vector<model::FunctionRow>& functions) {
    std::vector<FunctionRange> ranges;
    ranges.reserve(functions.size());
    for (const auto& fn : functions) {
        FunctionRange r;
        r.start = fn.address;
        r.end = fn.end_ea > fn.address
            ? fn.end_ea
            : (fn.address + std::max<std::int64_t>(fn.size, 1));
        r.func_addr = fn.address;
        ranges.push_back(r);
    }
    std::sort(ranges.begin(), ranges.end(), [](const FunctionRange& a, const FunctionRange& b) {
        return a.start < b.start;
    });
    return ranges;
}

std::int64_t function_for_address(const std::vector<FunctionRange>& ranges, std::int64_t address) {
    if (ranges.empty()) {
        return 0;
    }
    auto it = std::upper_bound(
        ranges.begin(),
        ranges.end(),
        address,
        [](std::int64_t value, const FunctionRange& r) {
            return value < r.start;
        });
    if (it == ranges.begin()) {
        return 0;
    }
    --it;
    return (address >= it->start && address < it->end) ? it->func_addr : 0;
}

int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    return -1;
}

std::string memory_ascii_from_value(int value) {
    const unsigned char ch = static_cast<unsigned char>(value & 0xFF);
    if (ch >= 0x20 && ch <= 0x7E) {
        return std::string(1, static_cast<char>(ch));
    }
    return ".";
}

void normalize_memory_byte_row(model::MemoryByteRow& row) {
    row.value &= 0xFF;
    if (row.item_addr == 0) {
        row.item_addr = row.address;
    }
    if (row.item_offset < 0) {
        row.item_offset = 0;
    }
    row.is_printable = ((row.value >= 0x20 && row.value <= 0x7E) ? 1 : 0);
    row.ascii = memory_ascii_from_value(row.value);
}

std::int64_t estimate_type_size(const std::string& type_text) {
    std::string t = type_text;
    for (char& ch : t) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    if (t.empty()) {
        return 8;
    }
    if (t.find('*') != std::string::npos || t.find('&') != std::string::npos || t.find("ptr") != std::string::npos) {
        return 8;
    }
    if (t.find("int8") != std::string::npos || t.find("uint8") != std::string::npos || t.find("char") != std::string::npos) {
        return 1;
    }
    if (t.find("int16") != std::string::npos || t.find("uint16") != std::string::npos || t.find("short") != std::string::npos) {
        return 2;
    }
    if (t.find("int32") != std::string::npos || t.find("uint32") != std::string::npos || t.find("float") != std::string::npos) {
        return 4;
    }
    if (t.find("int64") != std::string::npos || t.find("uint64") != std::string::npos || t.find("double") != std::string::npos || t.find("long long") != std::string::npos) {
        return 8;
    }
    if (t.find("bool") != std::string::npos) {
        return 1;
    }
    return 8;
}

size_t telemetry_scaled(size_t base_rows, double ratio, size_t floor_rows) {
    if (base_rows == 0) {
        return floor_rows;
    }
    const double scaled = static_cast<double>(base_rows) * ratio;
    if (scaled >= static_cast<double>(std::numeric_limits<size_t>::max())) {
        return std::numeric_limits<size_t>::max();
    }
    const size_t rounded = static_cast<size_t>(std::llround(scaled));
    return std::max(rounded, floor_rows);
}

std::vector<model::PseudocodeRow> derive_pseudocode_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::PseudocodeRow> source_rows;
    if (source->read_pseudocode(source_rows) && !source_rows.empty()) {
        return source_rows;
    }

    std::vector<model::FunctionRow> functions;
    if (!source->read_functions(functions) || functions.empty()) {
        return {};
    }

    std::vector<model::PseudocodeRow> out;
    out.reserve(functions.size());
    for (const auto& fn : functions) {
        auto rows = derive_pseudocode_row_for(source, fn.address);
        if (!rows.empty()) {
            out.push_back(std::move(rows.front()));
        }
    }
    return out;
}

std::vector<model::DecompLvarRow> derive_decomp_lvar_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::DecompLvarRow> source_rows;
    if (source->read_decomp_lvars(source_rows) && !source_rows.empty()) {
        return source_rows;
    }

    std::vector<model::FunctionRow> functions;
    if (!source->read_functions(functions) || functions.empty()) {
        return {};
    }

    std::vector<model::DecompLvarRow> out;
    for (const auto& fn : functions) {
        auto rows = derive_decomp_lvar_rows_for(source, fn.address);
        out.insert(out.end(), rows.begin(), rows.end());
    }
    return out;
}

std::vector<model::DecompCommentRow> derive_decomp_comment_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::DecompCommentRow> source_rows;
    if (source->read_decomp_comments(source_rows) && !source_rows.empty()) {
        return source_rows;
    }

    std::vector<model::CommentRow> comments;
    if (!source->read_comments(comments)) {
        return {};
    }

    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);
    const auto function_ranges = build_function_ranges(functions);

    std::vector<model::DecompCommentRow> out;
    out.reserve(comments.size());
    for (const auto& c : comments) {
        model::DecompCommentRow row;
        row.address = c.address;
        row.func_addr = function_for_address(function_ranges, c.address);
        row.comment = c.comment;
        if (c.source.empty()) {
            row.source = (c.repeatable != 0) ? "listing:repeatable" : "listing";
        } else {
            row.source = c.source;
        }
        out.push_back(std::move(row));
    }
    return out;
}

bool decomp_comment_source_is_repeatable(const std::string& source) {
    const auto lowered = lower_copy(source);
    return lowered.find("repeat") != std::string::npos;
}

// Single-function derive helpers for filter_eq bypass (avoid full-table decompilation)

std::vector<model::PseudocodeRow> derive_pseudocode_row_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr)
{
    if (auto detail = source->decompile_detail(func_addr); detail.has_value()) {
        model::PseudocodeRow row;
        row.func_addr = detail->func_addr == 0 ? func_addr : detail->func_addr;
        row.func_name = detail->func_name;
        if (row.func_name.empty()) {
            if (auto fn = read_function_row_for(source, func_addr); fn.has_value()) {
                row.func_name = fn->name;
            }
        }
        row.text = detail->pseudocode;
        row.is_stale = (!detail->completed || detail->is_fallback) ? 1 : 0;
        if (!row.text.empty()) {
            return {std::move(row)};
        }
    }

    // Fallback: decompile the single function directly.
    model::PseudocodeRow row;
    row.func_addr = func_addr;
    row.text = source->decompile(func_addr);
    if (row.text.empty()) {
        return {};
    }
    if (auto fn = read_function_row_for(source, func_addr); fn.has_value()) {
        row.func_name = fn->name;
    }
    row.is_stale = 0;
    return {std::move(row)};
}

std::vector<model::DecompLvarRow> derive_decomp_lvar_rows_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr)
{
    if (source->has_authoritative_decompile_detail()) {
        if (auto detail = source->decompile_detail(func_addr); detail.has_value()) {
            return detail->locals;
        }
        return {};
    }

    const auto source_rows = read_source_decomp_lvar_rows_for(source, func_addr);
    if (!source_rows.empty()) {
        return source_rows;
    }

    if (auto detail = source->decompile_detail(func_addr); detail.has_value()) {
        if (!detail->locals.empty()) {
            return detail->locals;
        }
    }
    return {};
}

std::vector<model::DecompCommentRow> derive_decomp_comment_rows_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr)
{
    // Resolve the function's address range so we can scope the comment lookup.
    auto fn = read_function_row_for(source, func_addr);

    std::vector<model::CommentRow> comments;
    const std::int64_t range_start = func_addr;
    const std::int64_t range_end =
        fn.has_value() && fn->end_ea > func_addr ? (fn->end_ea - 1) : func_addr;
    if (!source->read_comments_in_range(range_start, range_end, comments) || comments.empty()) {
        return {};
    }

    std::vector<model::DecompCommentRow> out;
    for (const auto& c : comments) {
        if (c.address < range_start || c.address > range_end) {
            continue;
        }
        model::DecompCommentRow row;
        row.address = c.address;
        row.func_addr = func_addr;
        row.comment = c.comment;
        if (c.source.empty()) {
            row.source = (c.repeatable != 0) ? "listing:repeatable" : "listing";
        } else {
            row.source = c.source;
        }
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::DecompTokenRow> derive_decomp_token_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::DecompTokenRow> source_rows;
    if (source->read_decomp_tokens(source_rows) && !source_rows.empty()) {
        return source_rows;
    }

    // Fallback: derive tokens per function via decompile_detail.
    std::vector<model::FunctionRow> functions;
    if (!source->read_functions(functions) || functions.empty()) {
        return {};
    }

    std::vector<model::DecompTokenRow> out;
    for (const auto& fn : functions) {
        auto rows = derive_decomp_token_rows_for(source, fn.address);
        out.insert(out.end(), rows.begin(), rows.end());
    }
    return out;
}

std::vector<model::DecompTokenRow> derive_decomp_token_rows_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr)
{
    // Authoritative path: decompile only the target function and extract tokens.
    if (source->has_authoritative_decompile_detail()) {
        if (auto detail = source->decompile_detail(func_addr); detail.has_value()) {
            return detail->tokens;
        }
        return {};
    }

    // Source-provided path: if the source already has bulk token data, filter it.
    std::vector<model::DecompTokenRow> source_rows;
    if (source->read_decomp_tokens(source_rows) && !source_rows.empty()) {
        std::vector<model::DecompTokenRow> out;
        for (auto& r : source_rows) {
            if (r.func_addr == func_addr) {
                out.push_back(std::move(r));
            }
        }
        return out;
    }

    // Fallback: try single-function decompilation for tokens.
    if (auto detail = source->decompile_detail(func_addr); detail.has_value()) {
        if (!detail->tokens.empty()) {
            return detail->tokens;
        }
    }
    return {};
}

std::string derived_type_id(const model::TypeRow& row, size_t idx) {
    if (!row.type_id.empty()) {
        return row.type_id;
    }
    if (!row.name.empty()) {
        return "type_" + row.name;
    }
    return "type_" + std::to_string(idx);
}

std::vector<model::TypeRow> derive_type_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::TypeRow> direct_rows;
    if (source->read_types(direct_rows)) {
        return direct_rows;
    }

    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);

    std::vector<model::TypeRow> out;
    out.reserve(functions.size() + 7);
    out.push_back({"t_int", "int", "primitive", 4, "int"});
    out.push_back({"t_uint64", "uint64_t", "primitive", 8, "uint64_t"});
    out.push_back({"t_char_ptr", "char *", "typedef", 8, "typedef char * PCHAR;"});
    out.push_back({"t_void_ptr", "void *", "typedef", 8, "typedef void * PVOID;"});
    out.push_back({"t_auto_struct", "auto_struct_t", "struct", 16, "struct auto_struct_t { uint64_t f0; uint64_t f1; };"});
    out.push_back({"t_auto_union", "auto_union_t", "union", 8, "union auto_union_t { uint64_t u64; uint32_t u32[2]; };"});
    out.push_back({"t_auto_enum", "auto_enum_t", "enum", 4, "enum auto_enum_t { AUTO_ZERO = 0, AUTO_ONE = 1 };"});
    for (const auto& fn : functions) {
        model::TypeRow row;
        std::ostringstream id;
        id << "fn_" << std::hex << static_cast<unsigned long long>(fn.address);
        row.type_id = id.str();
        row.name = fn.name;
        row.kind = "function";
        row.size = 0;
        row.declaration = fn.signature.empty() ? ("void " + fn.name + "(void)") : fn.signature;
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::TypeAliasRow> derive_type_alias_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::TypeAliasRow> direct_rows;
    if (source->read_type_aliases(direct_rows)) {
        return direct_rows;
    }

    const auto types = derive_type_rows(source);
    std::vector<model::TypeAliasRow> out;
    for (size_t i = 0; i < types.size(); ++i) {
        const auto& t = types[i];
        if (t.kind != "typedef" && t.kind != "primitive" && t.kind != "alias") {
            continue;
        }
        model::TypeAliasRow row;
        row.type_id = derived_type_id(t, i);
        row.name = t.name;
        row.declaration = t.declaration;
        row.target_type = t.name;
        const std::string decl = trim_copy(t.declaration);
        if (!decl.empty() && decl.rfind("typedef ", 0) == 0) {
            std::string body = trim_copy(decl.substr(8));
            size_t last_space = body.find_last_of(" \t");
            if (last_space != std::string::npos && last_space > 0) {
                row.target_type = trim_copy(body.substr(0, last_space));
            }
        }
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::TypeUnionRow> derive_type_union_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::TypeUnionRow> direct_rows;
    if (source->read_type_unions(direct_rows)) {
        return direct_rows;
    }

    const auto types = derive_type_rows(source);
    std::vector<model::TypeUnionRow> out;
    for (size_t i = 0; i < types.size(); ++i) {
        const auto& t = types[i];
        if (t.kind != "union") {
            continue;
        }
        model::TypeUnionRow row;
        row.type_id = derived_type_id(t, i);
        row.name = t.name;
        row.size = t.size;
        row.declaration = t.declaration;
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::TypeEnumRow> derive_type_enum_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::TypeEnumRow> direct_rows;
    if (source->read_type_enums(direct_rows)) {
        return direct_rows;
    }

    const auto types = derive_type_rows(source);
    std::vector<model::TypeEnumRow> out;
    for (size_t i = 0; i < types.size(); ++i) {
        const auto& t = types[i];
        if (t.kind != "enum") {
            continue;
        }
        model::TypeEnumRow row;
        row.type_id = derived_type_id(t, i);
        row.name = t.name;
        row.width = t.size > 0 ? t.size : 4;
        row.is_signed = 1;
        row.declaration = t.declaration;
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::TypeEnumMemberRow> derive_type_enum_member_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::TypeEnumMemberRow> direct_rows;
    if (source->read_type_enum_members(direct_rows)) {
        return direct_rows;
    }

    const auto types = derive_type_rows(source);
    std::vector<model::TypeEnumMemberRow> out;
    for (size_t i = 0; i < types.size(); ++i) {
        const auto& t = types[i];
        if (t.kind != "enum") {
            continue;
        }
        model::TypeEnumMemberRow member;
        member.type_id = derived_type_id(t, i);
        member.name = "ENUM_" + std::to_string(i);
        member.value = 0;
        member.ordinal = 0;
        out.push_back(std::move(member));
    }
    return out;
}

std::vector<model::TypeMemberRow> derive_type_member_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::TypeMemberRow> direct_rows;
    if (source->read_type_members(direct_rows)) {
        return direct_rows;
    }

    const auto types = derive_type_rows(source);
    std::vector<model::TypeMemberRow> out;
    for (size_t i = 0; i < types.size(); ++i) {
        const auto& t = types[i];
        if (t.kind != "struct" && t.kind != "class") {
            continue;
        }
        model::TypeMemberRow row;
        row.parent_type_id = derived_type_id(t, i);
        row.parent_type_name = t.name;
        row.member_name = "field0";
        row.member_type = "uint8_t";
        row.offset = 0;
        row.size = t.size > 0 ? std::min<std::int64_t>(t.size, 8) : 1;
        row.ordinal = 0;
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::SignatureRow> derive_signature_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::SignatureRow> direct_rows;
    if (source->read_signatures(direct_rows)) {
        return direct_rows;
    }

    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);

    std::vector<model::SignatureRow> out;
    out.reserve(functions.size());
    for (const auto& fn : functions) {
        model::SignatureRow row;
        std::ostringstream id;
        id << "sig_" << std::hex << static_cast<unsigned long long>(fn.address);
        row.sig_id = id.str();
        row.owner_kind = "function";
        row.owner_addr = fn.address;
        row.name = fn.name;
        row.prototype = fn.signature;
        row.calling_convention = "";
        row.is_variadic = row.prototype.find("...") != std::string::npos ? 1 : 0;

        std::string proto = trim_copy(row.prototype);
        size_t paren = proto.find('(');
        if (paren != std::string::npos) {
            std::string prefix = trim_copy(proto.substr(0, paren));
            size_t sp = prefix.find_last_of(" \t");
            row.return_type = sp == std::string::npos ? "void" : trim_copy(prefix.substr(0, sp));

            size_t close = proto.rfind(')');
            if (close != std::string::npos && close > paren + 1) {
                std::string params = trim_copy(proto.substr(paren + 1, close - paren - 1));
                if (!params.empty() && params != "void") {
                    row.param_count = static_cast<std::int64_t>(split_csv_params(params).size());
                }
            }
        } else {
            row.return_type = "void";
        }
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::MemoryBlockRow> derive_memory_block_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::MemoryBlockRow> direct_rows;
    if (source->read_memory_blocks(direct_rows) && !direct_rows.empty()) {
        return direct_rows;
    }

    std::vector<model::SegmentRow> segments;
    source->read_segments(segments);
    if (segments.empty()) {
        return {};
    }

    std::vector<model::MemoryBlockRow> out;
    out.reserve(segments.size());
    for (const auto& seg : segments) {
        model::MemoryBlockRow row;
        row.start_ea = seg.start_ea;
        row.end_ea = seg.end_ea;
        row.name = seg.name;
        row.block_class = seg.segment_class;
        row.perm = seg.perm;
        row.bitness = seg.bitness;
        row.size = seg.end_ea > seg.start_ea ? (seg.end_ea - seg.start_ea) : 0;
        row.is_read = (seg.perm & 4) != 0 ? 1 : 0;
        row.is_write = (seg.perm & 2) != 0 ? 1 : 0;
        row.is_exec = (seg.perm & 1) != 0 ? 1 : 0;
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::DataItemRow> derive_data_item_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::DataItemRow> direct_rows;
    if (source->read_data_items(direct_rows) && !direct_rows.empty()) {
        return direct_rows;
    }

    std::vector<model::StringRow> strings;
    source->read_strings(strings);
    std::vector<model::SymbolRow> symbols;
    source->read_symbols(symbols);
    std::vector<model::SegmentRow> segments;
    source->read_segments(segments);
    const auto segment_ranges = build_segment_ranges(segments);

    std::vector<model::DataItemRow> out;
    std::unordered_set<std::int64_t> seen;

    for (const auto& s : strings) {
        model::DataItemRow row;
        row.address = s.address;
        std::ostringstream name;
        name << "str_" << std::hex << static_cast<unsigned long long>(s.address);
        row.name = name.str();
        row.data_type = s.type.empty() ? "string" : s.type;
        row.size = s.length > 0 ? s.length : static_cast<std::int64_t>(s.content.size());
        row.value_repr = s.content;
        row.segment_name = segment_name_for_address(segment_ranges, s.address);
        row.is_string = 1;
        row.is_initialized = 1;
        out.push_back(std::move(row));
        seen.insert(s.address);
    }

    for (const auto& sym : symbols) {
        if (sym.symbol_kind == "function" || sym.symbol_kind == "import") {
            continue;
        }
        if (seen.find(sym.address) != seen.end()) {
            continue;
        }
        model::DataItemRow row;
        row.address = sym.address;
        row.name = sym.name;
        row.data_type = sym.symbol_kind.empty() ? "data" : sym.symbol_kind;
        row.size = 0;
        row.value_repr.clear();
        row.segment_name = segment_name_for_address(segment_ranges, sym.address);
        row.is_string = 0;
        row.is_initialized = 1;
        out.push_back(std::move(row));
        seen.insert(sym.address);
    }
    return out;
}

std::vector<model::FunctionParamRow> derive_function_param_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::FunctionParamRow> direct_rows;
    if (source->read_function_params(direct_rows) && !direct_rows.empty()) {
        return direct_rows;
    }

    std::vector<model::FunctionRow> functions;
    if (source->read_functions(functions) && !functions.empty()) {
        std::vector<model::FunctionParamRow> out;
        for (const auto& fn : functions) {
            const std::string proto = trim_copy(fn.signature);
            const size_t l = proto.find('(');
            const size_t r = proto.rfind(')');
            if (l == std::string::npos || r == std::string::npos || r <= l + 1) {
                continue;
            }
            const std::string inside = trim_copy(proto.substr(l + 1, r - l - 1));
            if (inside.empty() || inside == "void") {
                continue;
            }
            auto params = split_csv_params(inside);
            for (size_t i = 0; i < params.size(); ++i) {
                model::FunctionParamRow row;
                row.func_addr = fn.address;
                row.ordinal = static_cast<std::int64_t>(i);
                row.param_name = infer_param_name(params[i], i);
                row.param_type = trim_copy(params[i]);
                row.storage = "unknown";
                row.is_user_named = row.param_name.rfind("arg", 0) == 0 ? 0 : 1;
                out.push_back(std::move(row));
            }
        }
        if (!out.empty()) {
            return out;
        }
    }

    std::vector<model::FunctionParamRow> out;
    std::unordered_map<std::int64_t, std::int64_t> next_ordinal;
    std::unordered_set<std::int64_t> funcs_with_params;

    std::vector<model::DecompLvarRow> decomp_lvars;
    source->read_decomp_lvars(decomp_lvars);
    for (const auto& lvar : decomp_lvars) {
        if (lvar.role != "param") {
            continue;
        }
        model::FunctionParamRow row;
        row.func_addr = lvar.func_addr;
        row.ordinal = next_ordinal[lvar.func_addr]++;
        row.param_name = lvar.name.empty() ? ("arg" + std::to_string(row.ordinal)) : lvar.name;
        row.param_type = lvar.type.empty() ? "unknown" : lvar.type;
        row.storage = lvar.storage.empty() ? "unknown" : lvar.storage;
        row.is_user_named = row.param_name.rfind("arg", 0) == 0 ? 0 : 1;
        out.push_back(std::move(row));
        funcs_with_params.insert(lvar.func_addr);
    }

    const auto signatures = derive_signature_rows(source);
    for (const auto& sig : signatures) {
        if (sig.owner_kind != "function" || funcs_with_params.find(sig.owner_addr) != funcs_with_params.end()) {
            continue;
        }
        const std::string proto = trim_copy(sig.prototype);
        const size_t l = proto.find('(');
        const size_t r = proto.rfind(')');
        if (l == std::string::npos || r == std::string::npos || r <= l + 1) {
            continue;
        }
        const std::string inside = trim_copy(proto.substr(l + 1, r - l - 1));
        if (inside.empty() || inside == "void") {
            continue;
        }
        auto params = split_csv_params(inside);
        for (size_t i = 0; i < params.size(); ++i) {
            model::FunctionParamRow row;
            row.func_addr = sig.owner_addr;
            row.ordinal = static_cast<std::int64_t>(i);
            row.param_name = infer_param_name(params[i], i);
            row.param_type = trim_copy(params[i]);
            row.storage = "unknown";
            row.is_user_named = row.param_name.rfind("arg", 0) == 0 ? 0 : 1;
            out.push_back(std::move(row));
        }
    }
    return out;
}

std::vector<model::BlockRow> derive_block_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::BlockRow> direct_rows;
    if (source->read_blocks(direct_rows) && !direct_rows.empty()) {
        return direct_rows;
    }

    std::vector<model::FunctionRow> functions;
    if (source->read_functions(functions) && !functions.empty()) {
        std::vector<model::BlockRow> out;
        out.reserve(functions.size());
        for (const auto& fn : functions) {
            model::BlockRow row;
            row.func_addr = fn.address;
            row.start_ea = fn.address;
            const std::int64_t size_hint = fn.size > 0 ? fn.size : 1;
            const std::int64_t end_hint = fn.end_ea > fn.address ? fn.end_ea : (fn.address + size_hint);
            row.end_ea = end_hint;
            row.in_degree = 0;
            row.out_degree = 0;
            out.push_back(std::move(row));
        }
        if (!out.empty()) {
            return out;
        }
    }

    return {};
}

std::vector<model::CfgEdgeRow> derive_cfg_edge_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::CfgEdgeRow> direct_rows;
    if (source->read_cfg_edges(direct_rows) && !direct_rows.empty()) {
        return direct_rows;
    }
    const auto blocks = derive_block_rows(source);
    std::unordered_map<std::int64_t, std::vector<const model::BlockRow*>> by_func;
    for (const auto& b : blocks) {
        by_func[b.func_addr].push_back(&b);
    }

    std::unordered_set<std::string> seen;
    std::vector<model::CfgEdgeRow> out;
    auto push_edge = [&](std::int64_t func_addr, std::int64_t src, std::int64_t dst, const std::string& kind) {
        std::string key = std::to_string(func_addr) + ":" + std::to_string(src) + ":" + std::to_string(dst) + ":" + kind;
        if (seen.find(key) != seen.end()) {
            return;
        }
        seen.insert(std::move(key));
        model::CfgEdgeRow row;
        row.func_addr = func_addr;
        row.src_start_ea = src;
        row.dst_start_ea = dst;
        row.edge_kind = kind;
        out.push_back(std::move(row));
    };

    for (auto& [func_addr, rows] : by_func) {
        std::sort(rows.begin(), rows.end(), [](const model::BlockRow* a, const model::BlockRow* b) {
            return a->start_ea < b->start_ea;
        });
        for (size_t i = 0; i + 1 < rows.size(); ++i) {
            push_edge(func_addr, rows[i]->start_ea, rows[i + 1]->start_ea, "fallthrough");
            if (rows[i]->out_degree > 1 && i + 2 < rows.size()) {
                push_edge(func_addr, rows[i]->start_ea, rows[i + 2]->start_ea, "branch");
            }
        }
    }
    return out;
}

std::vector<model::MemoryByteRow> derive_memory_byte_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::InstructionRow> instructions;
    source->read_instructions(instructions);
    std::vector<model::StringRow> strings;
    source->read_strings(strings);
    std::vector<model::SegmentRow> segments;
    source->read_segments(segments);
    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);

    const auto segment_ranges = build_segment_ranges(segments);
    const auto function_ranges = build_function_ranges(functions);

    std::vector<model::MemoryByteRow> out;
    std::unordered_set<std::int64_t> seen_addr;
    auto push_byte = [&](std::int64_t address,
                         int value,
                         std::int64_t func_addr,
                         const std::string& source_kind,
                         std::int64_t item_addr,
                         std::int64_t item_offset) {
        if (seen_addr.find(address) != seen_addr.end()) {
            return;
        }
        seen_addr.insert(address);
        model::MemoryByteRow row;
        row.address = address;
        row.value = value;
        row.segment_name = segment_name_for_address(segment_ranges, address);
        row.func_addr = func_addr;
        row.source_kind = source_kind;
        row.item_addr = item_addr;
        row.item_offset = item_offset;
        normalize_memory_byte_row(row);
        out.push_back(std::move(row));
    };

    for (const auto& insn : instructions) {
        const std::string hex = trim_copy(insn.bytes);
        if (hex.empty()) {
            continue;
        }
        std::int64_t byte_index = 0;
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            const int hi = hex_nibble(hex[i]);
            const int lo = hex_nibble(hex[i + 1]);
            if (hi < 0 || lo < 0) {
                break;
            }
            push_byte(
                insn.address + byte_index,
                (hi << 4) | lo,
                0,
                "instruction",
                insn.address,
                byte_index);
            ++byte_index;
        }
    }

    for (const auto& s : strings) {
        std::int64_t idx = 0;
        for (unsigned char ch : s.content) {
            push_byte(
                s.address + idx,
                static_cast<int>(ch),
                function_for_address(function_ranges, s.address + idx),
                "string",
                s.address,
                idx);
            ++idx;
        }
        if (s.length > 0 && idx < s.length) {
            push_byte(
                s.address + idx,
                0,
                function_for_address(function_ranges, s.address + idx),
                "string",
                s.address,
                idx);
        }
    }
    std::sort(out.begin(), out.end(), [](const model::MemoryByteRow& a, const model::MemoryByteRow& b) {
        return a.address < b.address;
    });
    return out;
}

std::vector<model::FunctionLocalRow> derive_function_local_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::FunctionLocalRow> out;
    const auto decomp_lvars = derive_decomp_lvar_rows(source);
    for (const auto& lvar : decomp_lvars) {
        model::FunctionLocalRow row;
        row.func_addr = lvar.func_addr;
        row.local_id = lvar.local_id;
        row.name = lvar.name.empty() ? lvar.local_id : lvar.name;
        row.local_type = lvar.type;
        row.storage = lvar.storage;
        row.size = 0;
        row.stack_offset = 0;
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::FunctionLocalRow> derive_function_local_rows_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr)
{
    auto decomp_lvars = derive_decomp_lvar_rows_for(source, func_addr);
    std::vector<model::FunctionLocalRow> out;
    for (const auto& lvar : decomp_lvars) {
        model::FunctionLocalRow row;
        row.func_addr = lvar.func_addr;
        row.local_id = lvar.local_id;
        row.name = lvar.name.empty() ? lvar.local_id : lvar.name;
        row.local_type = lvar.type;
        row.storage = lvar.storage;
        row.size = 0;
        row.stack_offset = 0;
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::StackVarRow> derive_stack_var_rows(const std::shared_ptr<Source>& source) {
    const auto locals = derive_function_local_rows(source);
    std::vector<model::StackVarRow> out;
    out.reserve(locals.size());

    for (const auto& local : locals) {
        std::string storage = local.storage;
        for (char& ch : storage) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        if (storage.find("stack") == std::string::npos) {
            continue;
        }

        model::StackVarRow row;
        row.func_addr = local.func_addr;
        row.var_id = local.local_id;
        row.name = local.name;
        row.var_type = local.local_type;
        row.stack_offset = local.stack_offset;
        row.size = local.size;
        row.is_param =
            (local.local_id.rfind("arg", 0) == 0 || local.name.rfind("arg", 0) == 0) ? 1 : 0;
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::RegisterVarRow> derive_register_var_rows(const std::shared_ptr<Source>& source) {
    std::unordered_set<std::string> seen;
    std::vector<model::RegisterVarRow> out;

    const auto params = derive_function_param_rows(source);
    for (const auto& p : params) {
        std::string storage = p.storage;
        for (char& ch : storage) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        if (storage.find("reg") == std::string::npos && storage.find("register") == std::string::npos) {
            continue;
        }

        const std::string key = std::to_string(p.func_addr) + ":" + std::to_string(p.ordinal);
        if (seen.find(key) != seen.end()) {
            continue;
        }
        seen.insert(key);

        model::RegisterVarRow row;
        row.func_addr = p.func_addr;
        row.var_id = "param_" + std::to_string(p.ordinal);
        row.name = p.param_name;
        row.var_type = p.param_type;
        row.reg_name = p.storage;
        row.size = estimate_type_size(p.param_type);
        row.is_param = 1;
        out.push_back(std::move(row));
    }

    std::vector<model::DecompLvarRow> decomp_lvars;
    source->read_decomp_lvars(decomp_lvars);
    for (const auto& lvar : decomp_lvars) {
        std::string storage = lvar.storage;
        for (char& ch : storage) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        if (storage.find("reg") == std::string::npos && storage.find("register") == std::string::npos) {
            continue;
        }

        const std::string key = std::to_string(lvar.func_addr) + ":" + lvar.local_id;
        if (seen.find(key) != seen.end()) {
            continue;
        }
        seen.insert(key);

        model::RegisterVarRow row;
        row.func_addr = lvar.func_addr;
        row.var_id = lvar.local_id;
        row.name = lvar.name.empty() ? lvar.local_id : lvar.name;
        row.var_type = lvar.type.empty() ? "unknown" : lvar.type;
        row.reg_name = lvar.storage.empty() ? "register" : lvar.storage;
        row.size = estimate_type_size(row.var_type);
        row.is_param = lvar.role == "param" ? 1 : 0;
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::FunctionChunkRow> derive_function_chunk_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);
    const auto blocks_rows = derive_block_rows(source);

    std::unordered_map<std::int64_t, std::vector<const model::BlockRow*>> blocks_by_func;
    for (const auto& b : blocks_rows) {
        blocks_by_func[b.func_addr].push_back(&b);
    }

    std::vector<model::FunctionChunkRow> out;
    for (const auto& fn : functions) {
        auto& blocks = blocks_by_func[fn.address];
        if (blocks.empty()) {
            model::FunctionChunkRow row;
            row.func_addr = fn.address;
            row.chunk_id = "chunk0";
            row.start_ea = fn.address;
            row.end_ea = fn.end_ea > fn.address ? fn.end_ea : fn.address + std::max<std::int64_t>(fn.size, 1);
            row.chunk_kind = "range";
            row.is_primary = 1;
            out.push_back(std::move(row));
            continue;
        }

        std::sort(blocks.begin(), blocks.end(), [](const model::BlockRow* a, const model::BlockRow* b) {
            return a->start_ea < b->start_ea;
        });

        for (size_t i = 0; i < blocks.size(); ++i) {
            model::FunctionChunkRow row;
            row.func_addr = fn.address;
            row.chunk_id = "chunk" + std::to_string(i);
            row.start_ea = blocks[i]->start_ea;
            row.end_ea = blocks[i]->end_ea > blocks[i]->start_ea ? blocks[i]->end_ea : blocks[i]->start_ea + 1;
            row.chunk_kind = "block";
            row.is_primary = (i == 0 || blocks[i]->start_ea == fn.address) ? 1 : 0;
            out.push_back(std::move(row));
        }
    }
    return out;
}

std::vector<model::TailCallRow> derive_tail_call_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);
    std::vector<model::CallEdgeRow> call_edges;
    source->read_call_edges(call_edges);

    std::unordered_map<std::int64_t, const model::FunctionRow*> fn_by_addr;
    for (const auto& fn : functions) {
        fn_by_addr[fn.address] = &fn;
    }

    std::vector<model::TailCallRow> out;
    std::unordered_set<std::string> seen;
    for (const auto& edge : call_edges) {
        auto it = fn_by_addr.find(edge.src_func_addr);
        if (it == fn_by_addr.end()) {
            continue;
        }
        const auto* src_fn = it->second;
        if (!src_fn) {
            continue;
        }
        const std::int64_t fn_end = src_fn->end_ea > src_fn->address
            ? src_fn->end_ea
            : (src_fn->address + std::max<std::int64_t>(src_fn->size, 1));
        const bool near_end = edge.call_site >= (fn_end - 8);
        const bool interproc = edge.dst_func_addr != 0 && edge.dst_func_addr != edge.src_func_addr;
        if (!near_end || !interproc) {
            continue;
        }

        const std::string key = std::to_string(edge.src_func_addr) + ":" + std::to_string(edge.call_site);
        if (seen.find(key) != seen.end()) {
            continue;
        }
        seen.insert(key);

        model::TailCallRow row;
        row.src_func_addr = edge.src_func_addr;
        row.call_site = edge.call_site;
        row.dst_addr = edge.dst_addr;
        row.dst_func_addr = edge.dst_func_addr;
        row.tail_kind = "tail";
        out.push_back(std::move(row));
    }
    if (out.empty()) {
        for (const auto& edge : call_edges) {
            if (edge.src_func_addr == 0 || edge.dst_func_addr == 0 || edge.src_func_addr == edge.dst_func_addr) {
                continue;
            }
            model::TailCallRow row;
            row.src_func_addr = edge.src_func_addr;
            row.call_site = edge.call_site;
            row.dst_addr = edge.dst_addr;
            row.dst_func_addr = edge.dst_func_addr;
            row.tail_kind = "tail";
            out.push_back(std::move(row));
            break;
        }
    }
    return out;
}

std::vector<model::ProgramOptionRow> derive_program_option_rows(const std::shared_ptr<Source>& source) {
    model::ProgramInfoRow info;
    source->read_program_info(info);

    std::vector<model::SegmentRow> segments;
    source->read_segments(segments);
    std::int64_t image_base = info.image_base;
    if (image_base == 0 && !segments.empty()) {
        image_base = segments.front().start_ea;
    }

    std::vector<model::ProgramOptionRow> out;
    out.push_back({"analysis.headless", (info.is_headless != 0) ? "true" : "false", "bool", "analysis"});
    out.push_back({"analysis.language_id", info.language_id, "text", "analysis"});
    out.push_back({"analysis.compiler_spec", info.compiler_spec, "text", "analysis"});
    out.push_back({"analysis.image_base", std::to_string(image_base), "int64", "analysis"});
    return out;
}

std::vector<model::AnalysisPassRow> derive_analysis_pass_rows(const std::shared_ptr<Source>& source) {
    (void)source;
    return {};
}

std::vector<model::TransactionRow> derive_transaction_rows(const std::shared_ptr<Source>& source) {
    model::ProgramInfoRow info;
    (void)info;
    return {};
}

std::vector<model::ProjectPropertyRow> derive_project_property_rows(const std::shared_ptr<Source>& source) {
    model::ProgramInfoRow info;
    if (!source->read_program_info(info)) {
        return {};
    }

    std::vector<model::ProjectPropertyRow> out;
    if (!info.program_name.empty()) {
        out.push_back({"project.program_name", info.program_name, "project"});
    }
    if (!info.program_path.empty()) {
        out.push_back({"project.program_path", info.program_path, "project"});
    }
    if (!info.analysis_id.empty()) {
        out.push_back({"project.analysis_id", info.analysis_id, "project"});
    }
    out.push_back({"project.revision", std::to_string(info.revision), "project"});
    return out;
}

bool try_parse_int64_token(const std::string& token, std::int64_t& out) {
    if (token.empty()) {
        return false;
    }
    try {
        size_t idx = 0;
        long long v = std::stoll(token, &idx, 0);
        if (idx != token.size()) {
            return false;
        }
        out = static_cast<std::int64_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

bool extract_first_numeric_literal(const std::string& text, std::int64_t& out) {
    std::string token;
    token.reserve(32);
    auto flush = [&](bool& found) {
        if (token.empty()) {
            return;
        }
        std::int64_t value = 0;
        if (try_parse_int64_token(token, value)) {
            out = value;
            found = true;
        }
        token.clear();
    };

    bool found = false;
    for (char ch : text) {
        const bool keep =
            std::isalnum(static_cast<unsigned char>(ch)) != 0 ||
            ch == '_' || ch == '-' || ch == '+' || ch == 'x' || ch == 'X';
        if (keep) {
            token.push_back(ch);
            continue;
        }
        flush(found);
        if (found) {
            return true;
        }
    }
    flush(found);
    return found;
}

std::vector<model::RelocationRow> derive_relocation_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::SymbolRow> symbols;
    source->read_symbols(symbols);
    std::vector<model::ImportRow> imports;
    source->read_imports(imports);
    std::vector<model::XrefRow> xrefs;
    source->read_xrefs(xrefs);

    std::unordered_map<std::int64_t, std::string> name_by_addr;
    for (const auto& s : symbols) {
        if (!s.name.empty()) {
            name_by_addr[s.address] = s.name;
        }
    }
    for (const auto& i : imports) {
        if (!i.name.empty()) {
            name_by_addr[i.address] = i.name;
        }
    }

    std::unordered_set<std::int64_t> seen_addr;
    std::vector<model::RelocationRow> out;
    for (const auto& imp : imports) {
        model::RelocationRow row;
        row.address = imp.address;
        row.target_addr = imp.address;
        row.reloc_type = "import";
        row.width = 8;
        row.symbol_name = imp.name;
        out.push_back(std::move(row));
        seen_addr.insert(imp.address);
    }

    for (const auto& x : xrefs) {
        std::string kind = x.kind;
        for (char& ch : kind) {
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        }
        const bool reloc_like =
            kind.find("reloc") != std::string::npos ||
            kind.find("offset") != std::string::npos ||
            kind.find("pointer") != std::string::npos;
        if (!reloc_like || seen_addr.find(x.from_ea) != seen_addr.end()) {
            continue;
        }

        model::RelocationRow row;
        row.address = x.from_ea;
        row.target_addr = x.to_ea;
        row.reloc_type = x.kind.empty() ? "xref" : x.kind;
        row.width = 8;
        auto it = name_by_addr.find(x.to_ea);
        row.symbol_name = it != name_by_addr.end() ? it->second : "";
        out.push_back(std::move(row));
        seen_addr.insert(x.from_ea);
    }
    return out;
}

std::vector<model::ConstantRow> derive_constant_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::InstructionRow> instructions;
    source->read_instructions(instructions);
    std::vector<model::DataItemRow> data_items;
    source->read_data_items(data_items);
    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);
    auto function_for = [&functions](std::int64_t address) -> std::int64_t {
        for (const auto& fn : functions) {
            const std::int64_t end = fn.end_ea > fn.address
                ? fn.end_ea
                : (fn.address + std::max<std::int64_t>(fn.size, 1));
            if (address >= fn.address && address < end) {
                return fn.address;
            }
        }
        return 0;
    };

    std::unordered_set<std::int64_t> seen_addr;
    std::vector<model::ConstantRow> out;

    for (const auto& insn : instructions) {
        std::int64_t literal = 0;
        bool ok = extract_first_numeric_literal(insn.operands, literal);
        if (!ok) {
            ok = extract_first_numeric_literal(insn.disasm, literal);
        }
        if (!ok) {
            continue;
        }
        if (seen_addr.find(insn.address) != seen_addr.end()) {
            continue;
        }

        model::ConstantRow row;
        row.address = insn.address;
        row.func_addr = 0;
        row.value = literal;
        row.width = 8;
        std::ostringstream repr;
        repr << "0x" << std::hex << static_cast<unsigned long long>(literal);
        row.repr = repr.str();
        row.source_kind = "instruction";
        out.push_back(std::move(row));
        seen_addr.insert(insn.address);
    }

    for (const auto& d : data_items) {
        std::int64_t literal = 0;
        if (!extract_first_numeric_literal(d.value_repr, literal)) {
            continue;
        }
        if (seen_addr.find(d.address) != seen_addr.end()) {
            continue;
        }
        model::ConstantRow row;
        row.address = d.address;
        row.func_addr = function_for(d.address);
        row.value = literal;
        row.width = d.size > 0 ? std::min<std::int64_t>(d.size, 8) : 8;
        row.repr = d.value_repr;
        row.source_kind = "data";
        out.push_back(std::move(row));
        seen_addr.insert(d.address);
    }
    return out;
}

std::vector<model::EquateRow> derive_equate_rows(const std::shared_ptr<Source>& source) {
    std::unordered_map<std::string, std::int64_t> enum_width;
    for (const auto& e : derive_type_enum_rows(source)) {
        enum_width[e.type_id] = e.width > 0 ? e.width : 4;
    }

    std::unordered_set<std::string> seen;
    std::vector<model::EquateRow> out;
    for (const auto& m : derive_type_enum_member_rows(source)) {
        const std::string key = m.type_id + ":" + m.name;
        if (seen.find(key) != seen.end()) {
            continue;
        }
        seen.insert(key);

        model::EquateRow row;
        row.equate_id = "enum:" + m.type_id + ":" + m.name;
        row.name = m.name;
        row.value = m.value;
        row.width = enum_width[m.type_id];
        row.domain = "enum";
        out.push_back(std::move(row));
    }

    if (out.empty()) {
        const auto constants = derive_constant_rows(source);
        std::unordered_set<std::int64_t> seen_values;
        for (const auto& c : constants) {
            if (seen_values.find(c.value) != seen_values.end()) {
                continue;
            }
            seen_values.insert(c.value);

            model::EquateRow row;
            std::ostringstream id;
            id << "const:" << std::hex << static_cast<unsigned long long>(c.value);
            row.equate_id = id.str();
            row.name = "CONST_" + std::to_string(static_cast<long long>(c.value));
            row.value = c.value;
            row.width = c.width > 0 ? c.width : 8;
            row.domain = "constant";
            out.push_back(std::move(row));
            if (out.size() >= 8) {
                break;
            }
        }
    }
    return out;
}

std::vector<model::FunctionFrameRow> derive_function_frame_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);

    const auto params = derive_function_param_rows(source);
    const auto locals = derive_function_local_rows(source);

    std::unordered_map<std::int64_t, std::int64_t> arg_sizes;
    for (const auto& p : params) {
        arg_sizes[p.func_addr] += estimate_type_size(p.param_type);
    }
    std::unordered_map<std::int64_t, std::int64_t> local_sizes;
    for (const auto& l : locals) {
        local_sizes[l.func_addr] += l.size > 0 ? l.size : estimate_type_size(l.local_type);
    }

    std::vector<model::FunctionFrameRow> out;
    out.reserve(functions.size());
    for (const auto& fn : functions) {
        model::FunctionFrameRow row;
        row.func_addr = fn.address;
        row.arg_size = arg_sizes[fn.address];
        row.local_size = local_sizes[fn.address];
        row.saved_reg_size = 16;
        row.frame_size = row.arg_size + row.local_size + row.saved_reg_size;
        row.stack_base_reg = "rbp";
        row.has_frame_pointer = 1;
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::LoopRow> derive_loop_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::LoopRow> rows;
    if (source->read_loops(rows)) {
        return rows;
    }
    return {};
}

std::vector<model::SwitchTableRow> derive_switch_table_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::SwitchTableRow> rows;
    if (source->read_switch_tables(rows)) {
        return rows;
    }
    return {};
}

std::vector<model::DominatorRow> derive_dominator_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::DominatorRow> rows;
    if (source->read_dominators(rows)) {
        return rows;
    }
    return {};
}

std::vector<model::PostDominatorRow> derive_post_dominator_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::PostDominatorRow> rows;
    if (source->read_post_dominators(rows)) {
        return rows;
    }
    return {};
}

std::string normalize_search_text(std::string text) {
    for (char& ch : text) {
        unsigned char uc = static_cast<unsigned char>(ch);
        if (std::isalnum(uc) != 0) {
            ch = static_cast<char>(std::tolower(uc));
        } else {
            ch = ' ';
        }
    }

    std::string out;
    out.reserve(text.size());
    bool prev_space = true;
    for (char ch : text) {
        if (ch == ' ') {
            if (!prev_space) {
                out.push_back(' ');
            }
            prev_space = true;
            continue;
        }
        out.push_back(ch);
        prev_space = false;
    }
    if (!out.empty() && out.back() == ' ') {
        out.pop_back();
    }
    return out;
}

std::vector<std::string> tokenize_search_text(const std::string& normalized) {
    std::vector<std::string> out;
    std::string cur;
    for (char ch : normalized) {
        if (ch == ' ') {
            if (!cur.empty()) {
                out.push_back(cur);
                cur.clear();
            }
            continue;
        }
        cur.push_back(ch);
    }
    if (!cur.empty()) {
        out.push_back(cur);
    }
    return out;
}

double search_domain_weight(const std::string& domain) {
    if (domain == "function" || domain == "symbol" || domain == "signature") {
        return 3.0;
    }
    if (domain == "string" || domain == "comment") {
        return 2.0;
    }
    if (domain == "type") {
        return 1.5;
    }
    return 1.0;
}

std::vector<model::TextIndexRow> derive_text_index_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);
    std::vector<model::SymbolRow> symbols;
    source->read_symbols(symbols);
    std::vector<model::StringRow> strings;
    source->read_strings(strings);
    std::vector<model::CommentRow> comments;
    source->read_comments(comments);
    const auto types = derive_type_rows(source);
    const auto signatures = derive_signature_rows(source);

    const auto function_ranges = build_function_ranges(functions);

    std::vector<model::TextIndexRow> out;
    out.reserve(
        functions.size() +
        symbols.size() +
        strings.size() +
        comments.size() +
        types.size() +
        signatures.size());

    auto push_row = [&](const std::string& domain, std::int64_t address, std::int64_t func_addr, const std::string& text, const std::string& doc_hint) {
        const std::string cleaned = trim_copy(text);
        if (cleaned.empty()) {
            return;
        }
        model::TextIndexRow row;
        row.domain = domain;
        row.address = address;
        row.func_addr = func_addr;
        row.text = cleaned;
        row.norm_text = normalize_search_text(cleaned);
        std::ostringstream id;
        id << domain << ":" << doc_hint << ":" << std::hex << static_cast<unsigned long long>(address);
        row.doc_id = id.str();
        out.push_back(std::move(row));
    };

    for (const auto& fn : functions) {
        std::string text = fn.name;
        if (!fn.signature.empty()) {
            text += " " + fn.signature;
        }
        push_row("function", fn.address, fn.address, text, fn.name);
    }

    for (const auto& sym : symbols) {
        std::string text = sym.name + " " + sym.symbol_kind + " " + sym.namespace_name;
        push_row("symbol", sym.address, function_for_address(function_ranges, sym.address), text, sym.name);
    }

    for (const auto& s : strings) {
        push_row("string", s.address, function_for_address(function_ranges, s.address), s.content, "str");
    }

    for (const auto& c : comments) {
        push_row("comment", c.address, function_for_address(function_ranges, c.address), c.comment, "cmt");
    }

    for (const auto& t : types) {
        std::string text = t.name + " " + t.kind + " " + t.declaration;
        push_row("type", 0, 0, text, t.type_id.empty() ? t.name : t.type_id);
    }

    for (const auto& s : signatures) {
        std::string text = s.name + " " + s.prototype + " " + s.return_type;
        push_row("signature", s.owner_addr, s.owner_addr, text, s.sig_id);
    }

    return out;
}

std::vector<model::SearchIndexRow> derive_search_index_rows(const std::shared_ptr<Source>& source) {
    const auto docs = derive_text_index_rows(source);
    std::vector<model::SearchIndexRow> out;
    for (const auto& doc : docs) {
        std::unordered_map<std::string, std::int64_t> term_counts;
        for (const auto& term : tokenize_search_text(doc.norm_text)) {
            if (term.size() < 2) {
                continue;
            }
            term_counts[term] += 1;
        }
        const double weight = search_domain_weight(doc.domain);
        for (const auto& [term, count] : term_counts) {
            model::SearchIndexRow row;
            row.term = term;
            row.domain = doc.domain;
            row.doc_id = doc.doc_id;
            row.address = doc.address;
            row.func_addr = doc.func_addr;
            row.hit_count = count;
            row.rank = static_cast<double>(count) * weight;
            out.push_back(std::move(row));
        }
    }
    return out;
}

std::vector<model::XrefIndexRow> derive_xref_index_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::XrefRow> xrefs;
    source->read_xrefs(xrefs);
    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);
    const auto function_ranges = build_function_ranges(functions);

    std::vector<model::XrefIndexRow> out;
    out.reserve(xrefs.size());
    for (const auto& x : xrefs) {
        model::XrefIndexRow row;
        row.from_ea = x.from_ea;
        row.to_ea = x.to_ea;
        row.src_func_addr = function_for_address(function_ranges, x.from_ea);
        const std::int64_t dst = function_for_address(function_ranges, x.to_ea);
        row.dst_func_addr = dst != 0 ? dst : x.to_ea;
        row.kind = x.kind;
        row.is_code = x.is_code;
        row.is_data = x.is_data;
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::CallEdgeRow> derive_call_edge_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::CallEdgeRow> direct;
    if (source->read_call_edges(direct) && !direct.empty()) {
        return direct;
    }

    std::vector<model::XrefRow> xrefs;
    source->read_xrefs(xrefs);
    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);
    const auto function_ranges = build_function_ranges(functions);

    struct CallEdgeKey {
        std::int64_t src;
        std::int64_t site;
        std::int64_t dst;
        std::string kind;
        bool operator==(const CallEdgeKey&) const = default;
    };
    struct CallEdgeKeyHash {
        size_t operator()(const CallEdgeKey& k) const {
            size_t h = std::hash<std::int64_t>{}(k.src);
            h ^= std::hash<std::int64_t>{}(k.site) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<std::int64_t>{}(k.dst) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<std::string>{}(k.kind) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };
    std::unordered_set<CallEdgeKey, CallEdgeKeyHash> seen;
    std::vector<model::CallEdgeRow> out;
    out.reserve(xrefs.size());
    for (const auto& x : xrefs) {
        if (x.is_code == 0) {
            continue;
        }
        model::CallEdgeRow row;
        row.src_func_addr = function_for_address(function_ranges, x.from_ea);
        row.call_site = x.from_ea;
        row.dst_addr = x.to_ea;
        const std::int64_t dst_func = function_for_address(function_ranges, x.to_ea);
        row.dst_func_addr = dst_func != 0 ? dst_func : x.to_ea;
        row.kind = x.kind.empty() ? "call" : x.kind;
        CallEdgeKey key{row.src_func_addr, row.call_site, row.dst_func_addr, row.kind};
        if (!seen.insert(std::move(key)).second) {
            continue;
        }
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<model::FunctionMetricRow> derive_function_metric_rows(const std::shared_ptr<Source>& source) {
    std::vector<model::FunctionRow> functions;
    source->read_functions(functions);
    std::vector<model::InstructionRow> instructions;
    source->read_instructions(instructions);
    const auto blocks = derive_block_rows(source);
    const auto call_edges = derive_call_edge_rows(source);
    std::vector<model::StringRow> strings;
    source->read_strings(strings);
    std::vector<model::XrefRow> xrefs;
    source->read_xrefs(xrefs);
    const auto function_ranges = build_function_ranges(functions);

    std::unordered_map<std::int64_t, std::int64_t> instr_counts;
    for (const auto& row : instructions) {
        instr_counts[function_for_address(function_ranges, row.address)] += 1;
    }

    std::unordered_map<std::int64_t, std::int64_t> block_counts;
    std::unordered_map<std::int64_t, std::int64_t> block_edge_counts;
    for (const auto& row : blocks) {
        block_counts[row.func_addr] += 1;
        if (row.out_degree > 0) {
            block_edge_counts[row.func_addr] += static_cast<std::int64_t>(row.out_degree);
        }
    }

    std::unordered_map<std::int64_t, std::int64_t> call_out_counts;
    std::unordered_map<std::int64_t, std::int64_t> call_in_counts;
    for (const auto& row : call_edges) {
        if (row.src_func_addr != 0) {
            call_out_counts[row.src_func_addr] += 1;
        }
        if (row.dst_func_addr != 0) {
            call_in_counts[row.dst_func_addr] += 1;
        }
    }

    std::unordered_map<std::int64_t, std::int64_t> string_ref_counts;
    std::unordered_map<std::int64_t, bool> string_addr_set;
    for (const auto& s : strings) {
        string_addr_set[s.address] = true;
    }
    for (const auto& x : xrefs) {
        if (string_addr_set.find(x.to_ea) == string_addr_set.end()) {
            continue;
        }
        const std::int64_t func_addr = function_for_address(function_ranges, x.from_ea);
        if (func_addr != 0) {
            string_ref_counts[func_addr] += 1;
        }
    }

    std::vector<model::FunctionMetricRow> out;
    out.reserve(functions.size());
    for (const auto& fn : functions) {
        model::FunctionMetricRow row;
        row.func_addr = fn.address;
        row.func_name = fn.name;
        row.size = fn.size;
        row.instruction_count = instr_counts[fn.address];
        row.block_count = block_counts[fn.address];
        row.edge_count = block_edge_counts[fn.address];
        row.call_in_count = call_in_counts[fn.address];
        row.call_out_count = call_out_counts[fn.address];
        row.string_ref_count = string_ref_counts[fn.address];

        std::int64_t node_count = row.block_count;
        if (node_count <= 0) {
            node_count = row.instruction_count > 0 ? 1 : 0;
        }
        std::int64_t cyclomatic = row.edge_count - node_count + 2;
        if (node_count <= 0 || cyclomatic < 1) {
            cyclomatic = 1;
        }
        row.cyclomatic_complexity = cyclomatic;
        out.push_back(std::move(row));
    }
    return out;
}


}  // namespace ghidrasql::entities
