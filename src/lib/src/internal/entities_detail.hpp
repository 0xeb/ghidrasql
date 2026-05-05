// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include "internal/entities.hpp"

#include <ghidrasql/source.hpp>
#include <xsql/database.hpp>
#include <xsql/json.hpp>
#include <xsql/vtable.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ghidrasql::entities {

struct SegmentRange {
    std::int64_t start = 0;
    std::int64_t end = 0;
    std::string name;
};

struct FunctionRange {
    std::int64_t start = 0;
    std::int64_t end = 0;
    std::int64_t func_addr = 0;
};

std::string build_row_counts_json(const std::shared_ptr<Source>& source);
std::string trim_copy(const std::string& input);
std::vector<std::string> split_csv_params(const std::string& params);
std::string infer_param_name(const std::string& param_decl, size_t idx);
std::string lower_copy(std::string text);
std::string parse_return_type_from_prototype(const std::string& prototype);
std::int64_t parse_param_count_from_prototype(const std::string& prototype);
std::string function_return_type(const model::FunctionRow& row);
std::int64_t function_arg_count(const model::FunctionRow& row);
std::string function_calling_convention(const model::FunctionRow& row);
std::string normalize_type_token(std::string text);
bool type_is_pointer_compat(const std::string& type_text);
bool type_is_void_compat(const std::string& type_text);
bool type_is_int_compat(const std::string& type_text);
bool type_is_integral_compat(const std::string& type_text);
const char* breakpoint_type_name(int type);
const char* breakpoint_loc_type_name(int loc_type);
std::int64_t function_for_address(
    const std::vector<model::FunctionRow>& functions,
    std::int64_t address);
std::vector<SegmentRange> build_segment_ranges(const std::vector<model::SegmentRow>& segments);
std::string segment_name_for_address(const std::vector<SegmentRange>& ranges, std::int64_t address);
std::vector<FunctionRange> build_function_ranges(const std::vector<model::FunctionRow>& functions);
std::int64_t function_for_address(const std::vector<FunctionRange>& ranges, std::int64_t address);
int hex_nibble(char ch);
std::string memory_ascii_from_value(int value);
void normalize_memory_byte_row(model::MemoryByteRow& row);
std::int64_t estimate_type_size(const std::string& type_text);
size_t telemetry_scaled(size_t base_rows, double ratio, size_t floor_rows = 1);
std::vector<model::PseudocodeRow> derive_pseudocode_rows(const std::shared_ptr<Source>& source);
std::vector<model::DecompLvarRow> derive_decomp_lvar_rows(const std::shared_ptr<Source>& source);
std::vector<model::DecompCommentRow> derive_decomp_comment_rows(const std::shared_ptr<Source>& source);
std::vector<model::DecompTokenRow> derive_decomp_token_rows(const std::shared_ptr<Source>& source);
bool decomp_comment_source_is_repeatable(const std::string& source);
std::vector<model::PseudocodeRow> derive_pseudocode_row_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr);
std::vector<model::DecompLvarRow> derive_decomp_lvar_rows_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr);
std::vector<model::DecompCommentRow> derive_decomp_comment_rows_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr);
std::vector<model::DecompTokenRow> derive_decomp_token_rows_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr);
std::string derived_type_id(const model::TypeRow& row, size_t idx);
std::vector<model::TypeRow> derive_type_rows(const std::shared_ptr<Source>& source);
std::vector<model::TypeAliasRow> derive_type_alias_rows(const std::shared_ptr<Source>& source);
std::vector<model::TypeUnionRow> derive_type_union_rows(const std::shared_ptr<Source>& source);
std::vector<model::TypeEnumRow> derive_type_enum_rows(const std::shared_ptr<Source>& source);
std::vector<model::TypeEnumMemberRow> derive_type_enum_member_rows(const std::shared_ptr<Source>& source);
std::vector<model::TypeMemberRow> derive_type_member_rows(const std::shared_ptr<Source>& source);
std::vector<model::SignatureRow> derive_signature_rows(const std::shared_ptr<Source>& source);
std::vector<model::MemoryBlockRow> derive_memory_block_rows(const std::shared_ptr<Source>& source);
std::vector<model::DataItemRow> derive_data_item_rows(const std::shared_ptr<Source>& source);
std::vector<model::FunctionParamRow> derive_function_param_rows(const std::shared_ptr<Source>& source);
std::vector<model::BlockRow> derive_block_rows(const std::shared_ptr<Source>& source);
std::vector<model::CfgEdgeRow> derive_cfg_edge_rows(const std::shared_ptr<Source>& source);
std::vector<model::MemoryByteRow> derive_memory_byte_rows(const std::shared_ptr<Source>& source);
std::vector<model::FunctionLocalRow> derive_function_local_rows(const std::shared_ptr<Source>& source);
std::vector<model::FunctionLocalRow> derive_function_local_rows_for(
    const std::shared_ptr<Source>& source, std::int64_t func_addr);
std::vector<model::StackVarRow> derive_stack_var_rows(const std::shared_ptr<Source>& source);
std::vector<model::RegisterVarRow> derive_register_var_rows(const std::shared_ptr<Source>& source);
std::vector<model::FunctionChunkRow> derive_function_chunk_rows(const std::shared_ptr<Source>& source);
std::vector<model::TailCallRow> derive_tail_call_rows(const std::shared_ptr<Source>& source);
std::vector<model::ProgramOptionRow> derive_program_option_rows(const std::shared_ptr<Source>& source);
std::vector<model::AnalysisPassRow> derive_analysis_pass_rows(const std::shared_ptr<Source>& source);
std::vector<model::TransactionRow> derive_transaction_rows(const std::shared_ptr<Source>& source);
std::vector<model::ProjectPropertyRow> derive_project_property_rows(const std::shared_ptr<Source>& source);
bool try_parse_int64_token(const std::string& token, std::int64_t& out);
bool extract_first_numeric_literal(const std::string& text, std::int64_t& out);
std::vector<model::RelocationRow> derive_relocation_rows(const std::shared_ptr<Source>& source);
std::vector<model::ConstantRow> derive_constant_rows(const std::shared_ptr<Source>& source);
std::vector<model::EquateRow> derive_equate_rows(const std::shared_ptr<Source>& source);
std::vector<model::FunctionFrameRow> derive_function_frame_rows(const std::shared_ptr<Source>& source);
std::vector<model::LoopRow> derive_loop_rows(const std::shared_ptr<Source>& source);
std::vector<model::SwitchTableRow> derive_switch_table_rows(const std::shared_ptr<Source>& source);
std::vector<model::DominatorRow> derive_dominator_rows(const std::shared_ptr<Source>& source);
std::vector<model::PostDominatorRow> derive_post_dominator_rows(const std::shared_ptr<Source>& source);
std::string normalize_search_text(std::string text);
std::vector<std::string> tokenize_search_text(const std::string& normalized);
double search_domain_weight(const std::string& domain);
std::vector<model::TextIndexRow> derive_text_index_rows(const std::shared_ptr<Source>& source);
std::vector<model::SearchIndexRow> derive_search_index_rows(const std::shared_ptr<Source>& source);
std::vector<model::XrefIndexRow> derive_xref_index_rows(const std::shared_ptr<Source>& source);
std::vector<model::CallEdgeRow> derive_call_edge_rows(const std::shared_ptr<Source>& source);
std::vector<model::FunctionMetricRow> derive_function_metric_rows(const std::shared_ptr<Source>& source);

void create_entity_views(xsql::Database& db);

}  // namespace ghidrasql::entities
