// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <ghidrasql/source.hpp>

namespace ghidrasql {
namespace {

class CallbackLiveSource final : public Source {
public:
    explicit CallbackLiveSource(SourceCallbacks callbacks)
        : callbacks_(std::move(callbacks))
    {}

    bool read_functions(std::vector<model::FunctionRow>& out) const override {
        return read_rows(callbacks_.read_functions, out);
    }

    bool read_segments(std::vector<model::SegmentRow>& out) const override {
        return read_rows(callbacks_.read_segments, out);
    }

    bool read_symbols(std::vector<model::SymbolRow>& out) const override {
        return read_rows(callbacks_.read_symbols, out);
    }

    bool read_imports(std::vector<model::ImportRow>& out) const override {
        return read_rows(callbacks_.read_imports, out);
    }

    bool read_exports(std::vector<model::ExportRow>& out) const override {
        return read_rows(callbacks_.read_exports, out);
    }

    bool read_strings(std::vector<model::StringRow>& out) const override {
        return read_rows(callbacks_.read_strings, out);
    }

    bool read_xrefs(std::vector<model::XrefRow>& out) const override {
        return read_rows(callbacks_.read_xrefs, out);
    }

    bool read_function_calls(std::vector<model::FunctionCallRow>& out) const override {
        return read_rows(callbacks_.read_function_calls, out);
    }

    bool read_call_edges(std::vector<model::CallEdgeRow>& out) const override {
        return read_rows(callbacks_.read_call_edges, out);
    }

    bool read_memory_blocks(std::vector<model::MemoryBlockRow>& out) const override {
        return read_rows(callbacks_.read_memory_blocks, out);
    }

    bool read_data_items(std::vector<model::DataItemRow>& out) const override {
        return read_rows(callbacks_.read_data_items, out);
    }

    bool read_blocks(std::vector<model::BlockRow>& out) const override {
        return read_rows(callbacks_.read_blocks, out);
    }

    bool read_cfg_edges(std::vector<model::CfgEdgeRow>& out) const override {
        return read_rows(callbacks_.read_cfg_edges, out);
    }

    bool read_switch_tables(std::vector<model::SwitchTableRow>& out) const override {
        return read_rows(callbacks_.read_switch_tables, out);
    }

    bool read_dominators(std::vector<model::DominatorRow>& out) const override {
        return read_rows(callbacks_.read_dominators, out);
    }

    bool read_post_dominators(std::vector<model::PostDominatorRow>& out) const override {
        return read_rows(callbacks_.read_post_dominators, out);
    }

    bool read_loops(std::vector<model::LoopRow>& out) const override {
        return read_rows(callbacks_.read_loops, out);
    }

    bool read_function_params(std::vector<model::FunctionParamRow>& out) const override {
        return read_rows(callbacks_.read_function_params, out);
    }

    bool read_instructions(std::vector<model::InstructionRow>& out) const override {
        return read_rows(callbacks_.read_instructions, out);
    }

    bool read_comments(std::vector<model::CommentRow>& out) const override {
        return read_rows(callbacks_.read_comments, out);
    }
    bool read_types(std::vector<model::TypeRow>& out) const override {
        return read_rows(callbacks_.read_types, out);
    }
    bool read_type_members(std::vector<model::TypeMemberRow>& out) const override {
        return read_rows(callbacks_.read_type_members, out);
    }
    bool read_type_enums(std::vector<model::TypeEnumRow>& out) const override {
        return read_rows(callbacks_.read_type_enums, out);
    }
    bool read_type_enum_members(std::vector<model::TypeEnumMemberRow>& out) const override {
        return read_rows(callbacks_.read_type_enum_members, out);
    }
    bool read_type_unions(std::vector<model::TypeUnionRow>& out) const override {
        return read_rows(callbacks_.read_type_unions, out);
    }
    bool read_type_aliases(std::vector<model::TypeAliasRow>& out) const override {
        return read_rows(callbacks_.read_type_aliases, out);
    }
    bool read_signatures(std::vector<model::SignatureRow>& out) const override {
        return read_rows(callbacks_.read_signatures, out);
    }

    bool read_breakpoints(std::vector<model::BreakpointRow>& out) const override {
        return read_rows(callbacks_.read_breakpoints, out);
    }
    bool read_bookmarks(std::vector<model::BookmarkRow>& out) const override {
        return read_rows(callbacks_.read_bookmarks, out);
    }

    bool read_program_info(model::ProgramInfoRow& out) const override {
        if (!callbacks_.read_program_info) {
            out = {};
            return false;
        }
        return callbacks_.read_program_info(out);
    }

    bool read_pseudocode(std::vector<model::PseudocodeRow>& out) const override {
        return read_rows(callbacks_.read_pseudocode, out);
    }

    bool read_decomp_lvars(std::vector<model::DecompLvarRow>& out) const override {
        return read_rows(callbacks_.read_decomp_lvars, out);
    }

    bool read_decomp_comments(std::vector<model::DecompCommentRow>& out) const override {
        return read_rows(callbacks_.read_decomp_comments, out);
    }

    bool read_decomp_tokens(std::vector<model::DecompTokenRow>& out) const override {
        return read_rows(callbacks_.read_decomp_tokens, out);
    }

    bool read_capabilities(std::vector<model::CapabilityRow>& out) const override {
        return read_rows(callbacks_.read_capabilities, out);
    }

    bool read_parity_findings(std::vector<model::ParityFindingRow>& out) const override {
        return read_rows(callbacks_.read_parity_findings, out);
    }

    bool read_perf_benchmarks(std::vector<model::PerfBenchmarkRow>& out) const override {
        return read_rows(callbacks_.read_perf_benchmarks, out);
    }

    bool read_live_meta(std::vector<model::LiveMetaRow>& out) const override {
        return read_rows(callbacks_.read_live_meta, out);
    }

    bool rename_function(std::int64_t address, const std::string& new_name) override {
        return call_write(callbacks_.rename_function, address, new_name);
    }

    bool rename_symbol(std::int64_t address, const std::string& new_name) override {
        return call_write(callbacks_.rename_symbol, address, new_name);
    }

    bool delete_symbol(std::int64_t address, const std::string& name) override {
        return call_write(callbacks_.delete_symbol, address, name);
    }

    bool rename_data_item(std::int64_t address, const std::string& new_name) override {
        return call_write(callbacks_.rename_data_item, address, new_name);
    }

    bool set_data_item_type(std::int64_t address, const std::string& new_type) override {
        return call_write(callbacks_.set_data_item_type, address, new_type);
    }

    bool delete_data_item(std::int64_t address) override {
        return call_write(callbacks_.delete_data_item, address);
    }

    bool set_comment(std::int64_t address, const std::string& comment, bool repeatable) override {
        return call_write(callbacks_.set_comment, address, comment, repeatable);
    }

    bool delete_comment(std::int64_t address, bool repeatable) override {
        return call_write(callbacks_.delete_comment, address, repeatable);
    }

    bool set_comment_by_kind(std::int64_t address, const std::string& comment, const std::string& kind) override {
        return call_write(callbacks_.set_comment_by_kind, address, comment, kind);
    }

    bool delete_comment_by_kind(std::int64_t address, const std::string& kind) override {
        return call_write(callbacks_.delete_comment_by_kind, address, kind);
    }

    bool rename_decomp_local(
        std::int64_t func_addr,
        const std::string& local_id,
        const std::string& new_name) override
    {
        return call_write(callbacks_.rename_decomp_local, func_addr, local_id, new_name);
    }

    bool set_decomp_local_type(
        std::int64_t func_addr,
        const std::string& local_id,
        const std::string& new_type) override
    {
        return call_write(callbacks_.set_decomp_local_type, func_addr, local_id, new_type);
    }

    bool rename_function_param(
        std::int64_t func_addr,
        std::int64_t ordinal,
        const std::string& new_name) override
    {
        return call_write(callbacks_.rename_function_param, func_addr, ordinal, new_name);
    }

    bool set_function_param_type(
        std::int64_t func_addr,
        std::int64_t ordinal,
        const std::string& new_type) override
    {
        return call_write(callbacks_.set_function_param_type, func_addr, ordinal, new_type);
    }

    bool add_breakpoint(
        std::int64_t address,
        int type,
        std::int64_t size,
        const std::string& condition,
        const std::string& group) override
    {
        return call_write(callbacks_.add_breakpoint, address, type, size, condition, group);
    }

    bool set_breakpoint_enabled(std::int64_t address, bool enabled) override {
        return call_write(callbacks_.set_breakpoint_enabled, address, enabled);
    }

    bool set_breakpoint_type(std::int64_t address, int type) override {
        return call_write(callbacks_.set_breakpoint_type, address, type);
    }

    bool set_breakpoint_size(std::int64_t address, std::int64_t size) override {
        return call_write(callbacks_.set_breakpoint_size, address, size);
    }

    bool set_breakpoint_condition(std::int64_t address, const std::string& condition) override {
        return call_write(callbacks_.set_breakpoint_condition, address, condition);
    }

    bool set_breakpoint_group(std::int64_t address, const std::string& group) override {
        return call_write(callbacks_.set_breakpoint_group, address, group);
    }

    bool delete_breakpoint(std::int64_t address) override {
        return call_write(callbacks_.delete_breakpoint, address);
    }

    bool add_bookmark(
        std::int64_t address,
        const std::string& type,
        const std::string& category,
        const std::string& comment) override
    {
        return call_write(callbacks_.add_bookmark, address, type, category, comment);
    }

    bool set_bookmark_type(
        std::int64_t address,
        const std::string& old_type,
        const std::string& old_category,
        const std::string& new_type) override
    {
        return call_write(callbacks_.set_bookmark_type, address, old_type, old_category, new_type);
    }

    bool set_bookmark_category(
        std::int64_t address,
        const std::string& type,
        const std::string& old_category,
        const std::string& new_category) override
    {
        return call_write(callbacks_.set_bookmark_category, address, type, old_category, new_category);
    }

    bool set_bookmark_comment(
        std::int64_t address,
        const std::string& type,
        const std::string& category,
        const std::string& comment) override
    {
        return call_write(callbacks_.set_bookmark_comment, address, type, category, comment);
    }

    bool delete_bookmark(
        std::int64_t address,
        const std::string& type,
        const std::string& category) override
    {
        return call_write(callbacks_.delete_bookmark, address, type, category);
    }

    bool rename_type(const std::string& type_id, const std::string& new_name) override {
        return call_write(callbacks_.rename_type, type_id, new_name);
    }

    bool create_type(
        const std::string& name,
        const std::string& kind,
        std::int64_t size,
        const std::string& declaration) override
    {
        return call_write(callbacks_.create_type, name, kind, size, declaration);
    }

    bool delete_type(const std::string& type_id) override {
        return call_write(callbacks_.delete_type, type_id);
    }

    bool create_type_alias(
        const std::string& name,
        const std::string& target_type) override
    {
        return call_write(callbacks_.create_type_alias, name, target_type);
    }

    bool delete_type_alias(const std::string& type_id) override {
        return call_write(callbacks_.delete_type_alias, type_id);
    }

    bool set_type_alias_target(
        const std::string& type_id,
        const std::string& target_type) override
    {
        return call_write(callbacks_.set_type_alias_target, type_id, target_type);
    }

    bool create_type_enum(
        const std::string& name,
        std::int64_t width,
        bool is_signed) override
    {
        return call_write(callbacks_.create_type_enum, name, width, is_signed);
    }

    bool delete_type_enum(const std::string& type_id) override {
        return call_write(callbacks_.delete_type_enum, type_id);
    }

    bool add_type_enum_member(
        const std::string& type_id,
        const std::string& name,
        std::int64_t value) override
    {
        return call_write(callbacks_.add_type_enum_member, type_id, name, value);
    }

    bool delete_type_enum_member(
        const std::string& type_id,
        std::int64_t ordinal) override
    {
        return call_write(callbacks_.delete_type_enum_member, type_id, ordinal);
    }

    bool rename_type_member(
        const std::string& parent_type_id,
        std::int64_t ordinal,
        const std::string& new_name) override
    {
        return call_write(callbacks_.rename_type_member, parent_type_id, ordinal, new_name);
    }

    bool add_type_member(
        const std::string& parent_type_id,
        const std::string& member_name,
        const std::string& member_type,
        std::int64_t size) override
    {
        return call_write(callbacks_.add_type_member, parent_type_id, member_name, member_type, size);
    }

    bool delete_type_member(
        const std::string& parent_type_id,
        std::int64_t ordinal) override
    {
        return call_write(callbacks_.delete_type_member, parent_type_id, ordinal);
    }

    bool set_type_member_type(
        const std::string& parent_type_id,
        std::int64_t ordinal,
        const std::string& new_type) override
    {
        return call_write(callbacks_.set_type_member_type, parent_type_id, ordinal, new_type);
    }

    bool rename_type_enum_member(
        const std::string& type_id,
        std::int64_t ordinal,
        const std::string& new_name) override
    {
        return call_write(callbacks_.rename_type_enum_member, type_id, ordinal, new_name);
    }

    bool set_type_enum_member_value(
        const std::string& type_id,
        std::int64_t ordinal,
        std::int64_t new_value) override
    {
        return call_write(callbacks_.set_type_enum_member_value, type_id, ordinal, new_value);
    }

    bool set_type_member_comment(
        const std::string& parent_type_id,
        std::int64_t ordinal,
        const std::string& comment) override
    {
        return call_write(callbacks_.set_type_member_comment, parent_type_id, ordinal, comment);
    }

    bool set_type_enum_member_comment(
        const std::string& type_id,
        std::int64_t ordinal,
        const std::string& comment) override
    {
        return call_write(callbacks_.set_type_enum_member_comment, type_id, ordinal, comment);
    }

    bool create_type_union(
        const std::string& name,
        std::int64_t size,
        const std::string& declaration) override
    {
        return call_write(callbacks_.create_type_union, name, size, declaration);
    }

    bool delete_type_union(const std::string& type_id) override {
        return call_write(callbacks_.delete_type_union, type_id);
    }

    bool set_function_signature(
        std::int64_t owner_addr,
        const std::string& prototype) override
    {
        return call_write(callbacks_.set_function_signature, owner_addr, prototype);
    }

    bool create_symbol(std::int64_t address, const std::string& name) override {
        return call_write(callbacks_.create_symbol, address, name);
    }

    bool create_data_item(std::int64_t address, const std::string& data_type, const std::string& name) override {
        return call_write(callbacks_.create_data_item, address, data_type, name);
    }

    bool write_byte(std::int64_t address, std::uint8_t value) override {
        return call_write(callbacks_.write_byte, address, value);
    }

    bool save_database() override {
        if (callbacks_.save_database) {
            return callbacks_.save_database();
        }
        return false;
    }

    bool discard_changes() override {
        if (!callbacks_.discard_changes) {
            return false;
        }
        if (!callbacks_.discard_changes()) {
            return false;
        }
        return refresh();
    }

    bool refresh() override {
        if (!callbacks_.refresh) {
            return true;
        }
        return callbacks_.refresh();
    }

    int parse_declarations(const std::string& source_text) override {
        if (callbacks_.parse_declarations) {
            return callbacks_.parse_declarations(source_text);
        }
        return -1;
    }

    std::string decompile(std::int64_t address) const override {
        if (callbacks_.decompile) {
            return callbacks_.decompile(address);
        }
        return {};
    }

    std::optional<model::DecompilationDetail> decompile_detail(std::int64_t address) const override {
        if (callbacks_.decompile_detail) {
            return callbacks_.decompile_detail(address);
        }
        return Source::decompile_detail(address);
    }

    bool has_authoritative_decompile_detail() const override {
        return static_cast<bool>(callbacks_.decompile_detail);
    }

private:
    template <typename Row>
    bool read_rows(
        const std::function<bool(std::vector<Row>&)>& callback,
        std::vector<Row>& out) const
    {
        if (!callback) {
            out.clear();
            return false;
        }
        return callback(out);
    }

    template <typename Fn, typename... Args>
    bool call_write(const Fn& fn, Args&&... args) {
        if (!fn) {
            return false;
        }
        return fn(std::forward<Args>(args)...);
    }

    SourceCallbacks callbacks_;
};

}  // namespace

std::shared_ptr<Source> create_callback_live_source(SourceCallbacks callbacks) {
    return std::make_shared<CallbackLiveSource>(std::move(callbacks));
}

}  // namespace ghidrasql
