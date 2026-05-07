// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <ghidrasql/source.hpp>

namespace ghidrasql {
namespace {

template <typename Row>
bool clear_and_fail(std::vector<Row>& out) {
    out.clear();
    return false;
}

}  // namespace

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
bool Source::read_blocks(std::vector<model::BlockRow>& out) const { return clear_and_fail(out); }
bool Source::read_cfg_edges(std::vector<model::CfgEdgeRow>& out) const { return clear_and_fail(out); }
bool Source::read_switch_tables(std::vector<model::SwitchTableRow>& out) const { return clear_and_fail(out); }
bool Source::read_dominators(std::vector<model::DominatorRow>& out) const { return clear_and_fail(out); }
bool Source::read_post_dominators(std::vector<model::PostDominatorRow>& out) const { return clear_and_fail(out); }
bool Source::read_loops(std::vector<model::LoopRow>& out) const { return clear_and_fail(out); }
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
                detail.locals.push_back(local);
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
