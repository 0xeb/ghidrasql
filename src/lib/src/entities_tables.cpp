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
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ghidrasql::entities {

// Helper: build a write-error message, appending source detail if available.
inline void report_write_error(
    const std::shared_ptr<Source>& source,
    const std::string& message) {
    auto detail = source->last_error();
    xsql::set_vtab_error(detail.empty() ? message : message + ": " + detail);
}

constexpr std::int64_t kCommentsPerAddress = 0x10;
constexpr std::int64_t kRowsPerAddress = 0x1000;

inline std::int64_t encode_address_slot_rowid(std::int64_t address, size_t slot) {
    return address * kCommentsPerAddress + static_cast<std::int64_t>(slot);
}

inline bool decode_address_slot_rowid(std::int64_t raw_rowid, std::int64_t& address, size_t& slot) {
    if (raw_rowid < 0) {
        return false;
    }
    address = raw_rowid / kCommentsPerAddress;
    slot = static_cast<size_t>(raw_rowid % kCommentsPerAddress);
    return true;
}

inline std::int64_t encode_address_rowid(std::int64_t address, size_t slot) {
    return address * kRowsPerAddress + static_cast<std::int64_t>(slot);
}

inline bool decode_address_rowid(std::int64_t raw_rowid, std::int64_t& address, size_t& slot) {
    if (raw_rowid < 0) {
        return false;
    }
    address = raw_rowid / kRowsPerAddress;
    slot = static_cast<size_t>(raw_rowid % kRowsPerAddress);
    return true;
}

template <typename RowData>
struct QueryScopedIndexedRows {
    mutable std::mutex mu;
    std::vector<std::pair<std::int64_t, RowData>> rows;
    bool valid = false;

    void reset() {
        std::lock_guard<std::mutex> lk(mu);
        rows.clear();
        valid = false;
    }

    void store(std::vector<std::pair<std::int64_t, RowData>> indexed) {
        std::lock_guard<std::mutex> lk(mu);
        rows = std::move(indexed);
        valid = true;
    }

    bool lookup(std::int64_t rowid, RowData& out) const {
        std::lock_guard<std::mutex> lk(mu);
        if (!valid) {
            return false;
        }
        for (const auto& entry : rows) {
            if (entry.first == rowid) {
                out = entry.second;
                return true;
            }
        }
        return false;
    }
};

struct QueryScopedSearchRows {
    mutable std::mutex mu;
    std::vector<model::SearchIndexRow> rows;
    bool valid = false;

    void reset() {
        std::lock_guard<std::mutex> lk(mu);
        rows.clear();
        valid = false;
    }

    void store(std::vector<model::SearchIndexRow> next_rows) {
        std::lock_guard<std::mutex> lk(mu);
        rows = std::move(next_rows);
        valid = true;
    }

    std::vector<model::SearchIndexRow> snapshot() const {
        std::lock_guard<std::mutex> lk(mu);
        return rows;
    }
};

struct QueryScopeState {
    QueryScopedSearchRows search_index_rows;
    QueryScopedIndexedRows<model::FunctionLocalRow> function_local_rows;
    QueryScopedIndexedRows<model::DecompLvarRow> decomp_lvar_rows;

    void reset_all() {
        search_index_rows.reset();
        function_local_rows.reset();
        decomp_lvar_rows.reset();
    }

    void reset_for_table(const std::string& name) {
        if (name == "search_index") {
            search_index_rows.reset();
        } else if (name == "function_locals") {
            function_local_rows.reset();
        } else if (name == "decomp_lvars") {
            decomp_lvar_rows.reset();
        }
    }
};

// Helper: classify string encoding to avoid repeated find() calls.
enum class StringEncClass { kAscii, kUtf16, kUtf32 };

inline StringEncClass classify_string_encoding(const std::string& encoding) {
    const std::string enc = lower_copy(encoding);
    if (enc.find("utf16") != std::string::npos || enc.find("utf-16") != std::string::npos)
        return StringEncClass::kUtf16;
    if (enc.find("utf32") != std::string::npos || enc.find("utf-32") != std::string::npos)
        return StringEncClass::kUtf32;
    return StringEncClass::kAscii;
}

template <typename RowData>
class OwnedRowIterator final : public xsql::RowIterator {
public:
    using ColumnFn = std::function<void(xsql::FunctionContext&, int, const RowData&)>;

    OwnedRowIterator(std::vector<RowData> rows, ColumnFn column_fn)
        : rows_(std::move(rows))
        , column_fn_(std::move(column_fn)) {}

    bool next() override {
        if (cursor_ < rows_.size()) {
            ++cursor_;
            return true;
        }
        return false;
    }

    bool eof() const override {
        return cursor_ == 0 || cursor_ > rows_.size();
    }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (eof()) {
            ctx.result_null();
            return;
        }
        column_fn_(ctx, col, rows_[cursor_ - 1]);
    }

    std::int64_t rowid() const override {
        return cursor_ == 0 ? 0 : static_cast<std::int64_t>(cursor_ - 1);
    }

private:
    std::vector<RowData> rows_;
    ColumnFn column_fn_;
    size_t cursor_ = 0;
};

template <typename RowData>
class IndexedOwnedRowIterator final : public xsql::RowIterator {
public:
    using ColumnFn = std::function<void(xsql::FunctionContext&, int, const RowData&)>;

    IndexedOwnedRowIterator(std::vector<std::pair<std::int64_t, RowData>> rows, ColumnFn column_fn)
        : rows_(std::move(rows))
        , column_fn_(std::move(column_fn)) {}

    bool next() override {
        if (cursor_ < rows_.size()) {
            ++cursor_;
            return true;
        }
        return false;
    }

    bool eof() const override {
        return cursor_ == 0 || cursor_ > rows_.size();
    }

    void column(xsql::FunctionContext& ctx, int col) override {
        if (eof()) {
            ctx.result_null();
            return;
        }
        column_fn_(ctx, col, rows_[cursor_ - 1].second);
    }

    std::int64_t rowid() const override {
        return cursor_ == 0 ? 0 : rows_[cursor_ - 1].first;
    }

private:
    std::vector<std::pair<std::int64_t, RowData>> rows_;
    ColumnFn column_fn_;
    size_t cursor_ = 0;
};

inline bool arg_is_missing(int argc, xsql::FunctionArg* argv, int index) {
    return index < 0 || index >= argc || argv[index].is_null();
}

inline std::string arg_text_or(int argc, xsql::FunctionArg* argv, int index, const std::string& fallback = {}) {
    if (arg_is_missing(argc, argv, index)) {
        return fallback;
    }
    const char* text = argv[index].as_c_str();
    return text ? text : fallback;
}

inline std::optional<std::string> arg_text_opt(int argc, xsql::FunctionArg* argv, int index) {
    if (arg_is_missing(argc, argv, index)) {
        return std::nullopt;
    }
    const char* text = argv[index].as_c_str();
    return std::string(text ? text : "");
}

inline std::optional<std::int64_t> arg_int64_opt(int argc, xsql::FunctionArg* argv, int index) {
    if (arg_is_missing(argc, argv, index)) {
        return std::nullopt;
    }
    return argv[index].as_int64();
}

template <typename Row, typename DeriveAll, typename DeriveFor>
inline std::vector<std::pair<std::int64_t, Row>> derive_indexed_rows(
    const std::shared_ptr<Source>& source,
    DeriveAll derive_all,
    DeriveFor derive_for)
{
    std::vector<model::FunctionRow> functions;
    if (!source->read_functions(functions) || functions.empty()) {
        auto rows = derive_all(source);
        std::vector<std::pair<std::int64_t, Row>> indexed;
        indexed.reserve(rows.size());
        for (size_t i = 0; i < rows.size(); ++i) {
            indexed.emplace_back(static_cast<std::int64_t>(i), std::move(rows[i]));
        }
        return indexed;
    }
    std::vector<std::pair<std::int64_t, Row>> indexed;
    std::int64_t next_rowid = 0;
    for (const auto& fn : functions) {
        auto rows = derive_for(source, fn.address);
        for (auto& row : rows) {
            indexed.emplace_back(next_rowid++, std::move(row));
        }
    }
    return indexed;
}

inline std::vector<std::pair<std::int64_t, model::DecompLvarRow>> derive_indexed_decomp_lvar_rows(
    const std::shared_ptr<Source>& source)
{
    return derive_indexed_rows<model::DecompLvarRow>(
        source, derive_decomp_lvar_rows, derive_decomp_lvar_rows_for);
}

inline std::vector<std::pair<std::int64_t, model::FunctionLocalRow>> derive_indexed_function_local_rows(
    const std::shared_ptr<Source>& source)
{
    return derive_indexed_rows<model::FunctionLocalRow>(
        source, derive_function_local_rows, derive_function_local_rows_for);
}

inline bool comment_insert_common(
    const std::shared_ptr<Source>& source,
    const std::string& table_name,
    std::int64_t address,
    const std::optional<std::string>& comment_opt,
    const std::optional<std::string>& source_opt,
    bool repeatable)
{
    if (source_opt && !source_opt->empty()) {
        if (!source->set_comment_by_kind(address, comment_opt.value_or(""), *source_opt)) {
            xsql::set_vtab_error("INSERT INTO " + table_name + " failed: set_comment_by_kind at 0x" +
                std::to_string(address));
            return false;
        }
        return true;
    }

    if (!comment_opt) {
        xsql::set_vtab_error("INSERT INTO " + table_name + " requires comment or source");
        return false;
    }

    if (!source->set_comment(address, *comment_opt, repeatable)) {
        xsql::set_vtab_error("INSERT INTO " + table_name + " failed: set_comment at 0x" +
            std::to_string(address));
        return false;
    }
    return true;
}

inline void column_import(xsql::FunctionContext& ctx, int col, const model::ImportRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_text(r.name); return;
        case 2: ctx.result_text(r.module); return;
        default: ctx.result_null(); return;
    }
}

inline void column_export(xsql::FunctionContext& ctx, int col, const model::ExportRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_text(r.name); return;
        case 2: ctx.result_text(r.module); return;
        default: ctx.result_null(); return;
    }
}

inline void column_string(xsql::FunctionContext& ctx, int col, const model::StringRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_int64(r.address); return;
        case 2: ctx.result_int64(r.length); return;
        case 3: ctx.result_text(r.type); return;
        case 4:
            switch (classify_string_encoding(r.encoding)) {
                case StringEncClass::kUtf16: ctx.result_text("utf16"); return;
                case StringEncClass::kUtf32: ctx.result_text("utf32"); return;
                default: ctx.result_text("ascii"); return;
            }
        case 5:
            switch (classify_string_encoding(r.encoding)) {
                case StringEncClass::kUtf16: ctx.result_int(2); return;
                case StringEncClass::kUtf32: ctx.result_int(4); return;
                default: ctx.result_int(1); return;
            }
        case 6:
            switch (classify_string_encoding(r.encoding)) {
                case StringEncClass::kUtf16: ctx.result_text("2-byte"); return;
                case StringEncClass::kUtf32: ctx.result_text("4-byte"); return;
                default: ctx.result_text("1-byte"); return;
            }
        case 7: ctx.result_int(0); return;
        case 8: ctx.result_text("linear"); return;
        case 9: ctx.result_text(r.encoding); return;
        case 10: ctx.result_text(r.content); return;
        default: ctx.result_null(); return;
    }
}

inline void column_symbol(xsql::FunctionContext& ctx, int col, const model::SymbolRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_text(r.name); return;
        case 2: ctx.result_text(r.symbol_kind); return;
        case 3: ctx.result_text(r.namespace_name); return;
        case 4: ctx.result_int(r.is_primary); return;
        case 5: ctx.result_int(r.is_external); return;
        default: ctx.result_null(); return;
    }
}

inline std::optional<model::FunctionRow> find_function_row_by_address(
    const std::shared_ptr<Source>& source,
    std::int64_t func_addr) {
    model::FunctionRow row;
    if (!source->read_function_at(func_addr, row)) {
        return std::nullopt;
    }
    return row;
}

inline void column_function(xsql::FunctionContext& ctx, int col, const model::FunctionRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_int64(r.address); return;
        case 2: ctx.result_text(r.name); return;
        case 3: ctx.result_int64(r.size); return;
        case 4: ctx.result_int64(r.end_ea); return;
        case 5: ctx.result_int64(r.flags); return;
        case 6: ctx.result_text(r.namespace_name); return;
        case 7: ctx.result_text(r.signature); return;
        case 8: ctx.result_text(function_return_type(r)); return;
        case 9: ctx.result_int64(function_arg_count(r)); return;
        case 10: ctx.result_text(function_calling_convention(r)); return;
        case 11: ctx.result_int(type_is_pointer_compat(function_return_type(r)) ? 1 : 0); return;
        case 12: ctx.result_int(type_is_void_compat(function_return_type(r)) ? 1 : 0); return;
        case 13: ctx.result_int(type_is_int_compat(function_return_type(r)) ? 1 : 0); return;
        case 14: ctx.result_int(type_is_integral_compat(function_return_type(r)) ? 1 : 0); return;
        default: ctx.result_null(); return;
    }
}

inline void column_xref(xsql::FunctionContext& ctx, int col, const model::XrefRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.from_ea); return;
        case 1: ctx.result_int64(r.to_ea); return;
        case 2: ctx.result_text(r.kind); return;
        case 3: ctx.result_int(r.is_code); return;
        case 4: ctx.result_int(r.is_data); return;
        default: ctx.result_null(); return;
    }
}

inline void column_instruction(xsql::FunctionContext& ctx, int col, const model::InstructionRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_text(r.mnemonic); return;
        case 2: ctx.result_text(r.operands); return;
        case 3: ctx.result_text(r.disasm); return;
        case 4: ctx.result_int(r.size); return;
        case 5: ctx.result_text(r.bytes); return;
        default: ctx.result_null(); return;
    }
}

inline void column_data_item(xsql::FunctionContext& ctx, int col, const model::DataItemRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_text(r.name); return;
        case 2: ctx.result_text(r.data_type); return;
        case 3: ctx.result_int64(r.size); return;
        case 4: ctx.result_text(r.value_repr); return;
        case 5: ctx.result_text(r.segment_name); return;
        case 6: ctx.result_int(r.is_string); return;
        case 7: ctx.result_int(r.is_initialized); return;
        default: ctx.result_null(); return;
    }
}

inline void column_pseudocode(xsql::FunctionContext& ctx, int col, const model::PseudocodeRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.func_addr); return;
        case 1: ctx.result_text(r.func_name); return;
        case 2: ctx.result_text(r.text); return;
        case 3: ctx.result_int(r.is_stale); return;
        default: ctx.result_null(); return;
    }
}

inline void column_decomp_lvar(xsql::FunctionContext& ctx, int col, const model::DecompLvarRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.func_addr); return;
        case 1: ctx.result_text(r.local_id); return;
        case 2: ctx.result_text(r.name); return;
        case 3: ctx.result_text(r.type); return;
        case 4: ctx.result_text(r.storage); return;
        case 5: ctx.result_text(r.role); return;
        default: ctx.result_null(); return;
    }
}

inline void column_decomp_comment(xsql::FunctionContext& ctx, int col, const model::DecompCommentRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.func_addr); return;
        case 1: ctx.result_int64(r.address); return;
        case 2: ctx.result_text(r.comment); return;
        case 3: ctx.result_text(r.source); return;
        default: ctx.result_null(); return;
    }
}

inline void column_decomp_token(xsql::FunctionContext& ctx, int col, const model::DecompTokenRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.func_addr); return;
        case 1: ctx.result_int64(r.token_index); return;
        case 2: ctx.result_text(r.text); return;
        case 3: ctx.result_text(r.kind); return;
        case 4: ctx.result_int(r.line); return;
        case 5: ctx.result_int(r.column); return;
        case 6: ctx.result_text(r.var_name); return;
        case 7: ctx.result_text(r.var_type); return;
        case 8: ctx.result_text(r.var_storage); return;
        default: ctx.result_null(); return;
    }
}

inline void column_function_local(xsql::FunctionContext& ctx, int col, const model::FunctionLocalRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.func_addr); return;
        case 1: ctx.result_text(r.local_id); return;
        case 2: ctx.result_text(r.name); return;
        case 3: ctx.result_text(r.local_type); return;
        case 4: ctx.result_text(r.storage); return;
        case 5: ctx.result_int64(r.stack_offset); return;
        case 6: ctx.result_int64(r.size); return;
        default: ctx.result_null(); return;
    }
}


inline xsql::CachedTableDef<model::FunctionRow> define_funcs(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::FunctionRow>("funcs")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> rows;
            return source->read_functions(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source](std::vector<model::FunctionRow>& out) {
            if (!source->read_functions(out)) {
                out.clear();
            }
        })
        .column_int64("address", [](const model::FunctionRow& r) { return r.address; })
        .column_int64("start_ea", [](const model::FunctionRow& r) { return r.address; })
        .column_text_rw(
            "name",
            [](const model::FunctionRow& r) { return r.name; },
            [source](model::FunctionRow& row, const char* name) {
                const std::string next = name ? name : "";
                if (row.name == next) {
                    return true;
                }
                if (!source->rename_function(row.address, next)) {
                    report_write_error(
                        source,
                        "UPDATE funcs.name failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.name = next;
                return true;
            })
        .column_int64("size", [](const model::FunctionRow& r) { return r.size; })
        .column_int64("end_ea", [](const model::FunctionRow& r) { return r.end_ea; })
        .column_int64("flags", [](const model::FunctionRow& r) { return r.flags; })
        .column_text("namespace", [](const model::FunctionRow& r) { return r.namespace_name; })
        .column_text_rw(
            "signature",
            [](const model::FunctionRow& r) { return r.signature; },
            [source](model::FunctionRow& row, const char* prototype) {
                const std::string next = prototype ? prototype : "";
                if (row.signature == next) {
                    return true;
                }
                if (!source->set_function_signature(row.address, next)) {
                    report_write_error(
                        source,
                        "UPDATE funcs.signature failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.signature = next;
                return true;
            })
        .column_text("return_type", [](const model::FunctionRow& r) {
            return function_return_type(r);
        })
        .column_int64("arg_count", [](const model::FunctionRow& r) {
            return function_arg_count(r);
        })
        .column_text("calling_conv", [](const model::FunctionRow& r) {
            return function_calling_convention(r);
        })
        .column_int("return_is_ptr", [](const model::FunctionRow& r) {
            return type_is_pointer_compat(function_return_type(r)) ? 1 : 0;
        })
        .column_int("return_is_void", [](const model::FunctionRow& r) {
            return type_is_void_compat(function_return_type(r)) ? 1 : 0;
        })
        .column_int("return_is_int", [](const model::FunctionRow& r) {
            return type_is_int_compat(function_return_type(r)) ? 1 : 0;
        })
        .column_int("return_is_integral", [](const model::FunctionRow& r) {
            return type_is_integral_compat(function_return_type(r)) ? 1 : 0;
        })
        .row_lookup([source](model::FunctionRow& row, std::int64_t raw_rowid) {
            if (raw_rowid < 0) {
                return false;
            }
            auto matched = find_function_row_by_address(source, raw_rowid);
            if (!matched.has_value()) {
                return false;
            }
            row = *matched;
            return true;
        })
        .filter_eq("address",
            [source](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<std::pair<std::int64_t, model::FunctionRow>> rows;
                if (auto row = find_function_row_by_address(source, func_addr); row.has_value()) {
                    rows.emplace_back(func_addr, *row);
                }
                return std::make_unique<IndexedOwnedRowIterator<model::FunctionRow>>(
                    std::move(rows),
                    column_function);
            }, 2.0, 1.0)
        .index_on("address", [](const model::FunctionRow& r) { return r.address; })
        .build();
}

inline xsql::CachedTableDef<model::SegmentRow> define_segments(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::SegmentRow>("segments")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::SegmentRow> rows;
            return source->read_segments(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source](std::vector<model::SegmentRow>& out) {
            if (!source->read_segments(out)) {
                out.clear();
            }
        })
        .column_int64("start_ea", [](const model::SegmentRow& r) { return r.start_ea; })
        .column_int64("end_ea", [](const model::SegmentRow& r) { return r.end_ea; })
        .column_text("name", [](const model::SegmentRow& r) { return r.name; })
        .column_text("class", [](const model::SegmentRow& r) { return r.segment_class; })
        .column_int("perm", [](const model::SegmentRow& r) { return r.perm; })
        .column_int("bitness", [](const model::SegmentRow& r) { return r.bitness; })
        .index_on("start_ea", [](const model::SegmentRow& r) { return r.start_ea; })
        .build();
}

inline xsql::CachedTableDef<model::MemoryBlockRow> define_memory_blocks(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::MemoryBlockRow>("memory_blocks")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::MemoryBlockRow> rows;
            return source->read_memory_blocks(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source](std::vector<model::MemoryBlockRow>& out) {
            if (!source->read_memory_blocks(out)) {
                out = derive_memory_block_rows(source);
            }
        })
        .column_int64("start_ea", [](const model::MemoryBlockRow& r) { return r.start_ea; })
        .column_int64("end_ea", [](const model::MemoryBlockRow& r) { return r.end_ea; })
        .column_text("name", [](const model::MemoryBlockRow& r) { return r.name; })
        .column_text("class", [](const model::MemoryBlockRow& r) { return r.block_class; })
        .column_int("perm", [](const model::MemoryBlockRow& r) { return r.perm; })
        .column_int("bitness", [](const model::MemoryBlockRow& r) { return r.bitness; })
        .column_int64("size", [](const model::MemoryBlockRow& r) { return r.size; })
        .column_int("is_read", [](const model::MemoryBlockRow& r) { return r.is_read; })
        .column_int("is_write", [](const model::MemoryBlockRow& r) { return r.is_write; })
        .column_int("is_exec", [](const model::MemoryBlockRow& r) { return r.is_exec; })
        .index_on("start_ea", [](const model::MemoryBlockRow& r) { return r.start_ea; })
        .build();
}

inline xsql::CachedTableDef<model::MemoryByteRow> define_memory_bytes(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::MemoryByteRow>("memory_bytes")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::InstructionRow> rows;
            return source->read_instructions(rows) ? rows.size() * 4 : size_t(1000);
        })
        .cache_builder([source](std::vector<model::MemoryByteRow>& out) {
            out = derive_memory_byte_rows(source);
        })
        .column_int64("address", [](const model::MemoryByteRow& r) { return r.address; })
        .column_int_rw("value",
            [](const model::MemoryByteRow& r) { return r.value; },
            [source](model::MemoryByteRow& r, int v) {
                if (v < 0 || v > 255) {
                    xsql::set_vtab_error("memory_bytes.value must be 0-255");
                    return false;
                }
                if (!source->write_byte(r.address, static_cast<std::uint8_t>(v))) {
                    xsql::set_vtab_error("source rejected memory_bytes write");
                    return false;
                }
                r.value = v;
                r.is_printable = (v >= 0x20 && v <= 0x7E) ? 1 : 0;
                r.ascii = memory_ascii_from_value(v);
                return true;
            })
        .column_text("segment_name", [](const model::MemoryByteRow& r) { return r.segment_name; })
        .column_int64("func_addr", [](const model::MemoryByteRow& r) { return r.func_addr; })
        .column_text("source_kind", [](const model::MemoryByteRow& r) { return r.source_kind; })
        .column_int64("item_addr", [](const model::MemoryByteRow& r) { return r.item_addr; })
        .column_int64("item_offset", [](const model::MemoryByteRow& r) { return r.item_offset; })
        .column_int("is_printable", [](const model::MemoryByteRow& r) { return r.is_printable; })
        .column_text("ascii", [](const model::MemoryByteRow& r) { return r.ascii; })
        .index_on("address", [](const model::MemoryByteRow& r) { return r.address; })
        .index_on("func_addr", [](const model::MemoryByteRow& r) { return r.func_addr; })
        .index_on("item_addr", [](const model::MemoryByteRow& r) { return r.item_addr; })
        .build();
}

inline xsql::CachedTableDef<model::SymbolRow> define_names(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::SymbolRow>("names")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::SymbolRow> rows;
            return source->read_symbols(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source](std::vector<model::SymbolRow>& out) {
            if (!source->read_symbols(out)) {
                out.clear();
            }
        })
        .column_int64("address", [](const model::SymbolRow& r) { return r.address; })
        .column_text_rw(
            "name",
            [](const model::SymbolRow& r) { return r.name; },
            [source](model::SymbolRow& row, const char* name) {
                if (!source->rename_symbol(row.address, name ? name : "")) {
                    xsql::set_vtab_error("UPDATE names.name failed: rename_symbol at 0x" +
                        std::to_string(row.address));
                    return false;
                }
                return true;
            })
        .column_text("symbol_kind", [](const model::SymbolRow& r) { return r.symbol_kind; })
        .column_text("namespace", [](const model::SymbolRow& r) { return r.namespace_name; })
        .column_int("is_primary", [](const model::SymbolRow& r) { return r.is_primary; })
        .column_int("is_external", [](const model::SymbolRow& r) { return r.is_external; })
        .deletable([source](model::SymbolRow& row) {
            return source->delete_symbol(row.address, row.name);
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
                xsql::set_vtab_error("INSERT INTO names requires address and name");
                return false;
            }
            const std::int64_t address = argv[0].as_int64();
            const char* name = argv[1].as_c_str();
            if (!name || !name[0]) {
                xsql::set_vtab_error("INSERT INTO names: name must not be empty");
                return false;
            }
            if (!source->create_symbol(address, name)) {
                xsql::set_vtab_error("INSERT INTO names failed: create_symbol at 0x" +
                    std::to_string(address));
                return false;
            }
            return true;
        })
        .row_lookup([source](model::SymbolRow& row, std::int64_t raw_rowid) {
            std::int64_t address = 0;
            size_t slot = 0;
            if (!decode_address_rowid(raw_rowid, address, slot)) {
                return false;
            }
            std::vector<model::SymbolRow> rows;
            if (!source->read_symbols_at(address, rows) || slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .filter_eq("address",
            [source](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::SymbolRow> rows;
                source->read_symbols_at(address, rows);
                std::vector<std::pair<std::int64_t, model::SymbolRow>> indexed;
                indexed.reserve(rows.size());
                for (size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(encode_address_rowid(address, i), std::move(rows[i]));
                }
                return std::make_unique<IndexedOwnedRowIterator<model::SymbolRow>>(
                    std::move(indexed),
                    column_symbol);
            }, 1.0, 4.0)
        .index_on("address", [](const model::SymbolRow& r) { return r.address; })
        .build();
}

inline xsql::CachedTableDef<model::ImportRow> define_imports(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::ImportRow>("imports")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::ImportRow> rows;
            return source->read_imports(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source](std::vector<model::ImportRow>& out) {
            if (!source->read_imports(out)) {
                out.clear();
            }
        })
        .column_int64("address", [](const model::ImportRow& r) { return r.address; })
        .column_text("name", [](const model::ImportRow& r) { return r.name; })
        .column_text("module", [](const model::ImportRow& r) { return r.module; })
        .filter_eq_text(
            "module",
            [source](const char* module) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::ImportRow> all_rows;
                std::vector<model::ImportRow> rows;
                if (source->read_imports(all_rows)) {
                    const std::string needle = module ? module : "";
                    rows.reserve(all_rows.size());
                    for (const auto& row : all_rows) {
                        if (row.module == needle) {
                            rows.push_back(row);
                        }
                    }
                }
                return std::make_unique<OwnedRowIterator<model::ImportRow>>(std::move(rows), column_import);
            },
            8.0,
            32.0)
        .index_on("address", [](const model::ImportRow& r) { return r.address; })
        .build();
}

inline xsql::CachedTableDef<model::ExportRow> define_exports(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::ExportRow>("exports")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::ExportRow> rows;
            return source->read_exports(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source](std::vector<model::ExportRow>& out) {
            if (!source->read_exports(out)) {
                out.clear();
            }
        })
        .column_int64("address", [](const model::ExportRow& r) { return r.address; })
        .column_text("name", [](const model::ExportRow& r) { return r.name; })
        .column_text("module", [](const model::ExportRow& r) { return r.module; })
        .filter_eq_text(
            "module",
            [source](const char* module) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::ExportRow> all_rows;
                std::vector<model::ExportRow> rows;
                if (source->read_exports(all_rows)) {
                    const std::string needle = module ? module : "";
                    rows.reserve(all_rows.size());
                    for (const auto& row : all_rows) {
                        if (row.module == needle) {
                            rows.push_back(row);
                        }
                    }
                }
                return std::make_unique<OwnedRowIterator<model::ExportRow>>(std::move(rows), column_export);
            },
            8.0,
            16.0)
        .index_on("address", [](const model::ExportRow& r) { return r.address; })
        .build();
}

inline xsql::CachedTableDef<model::StringRow> define_strings(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::StringRow>("strings")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::StringRow> rows;
            return source->read_strings(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source](std::vector<model::StringRow>& out) {
            if (!source->read_strings(out)) {
                out.clear();
            }
        })
        .column_int64("address", [](const model::StringRow& r) { return r.address; })
        .column_int64("ea", [](const model::StringRow& r) { return r.address; })
        .column_int64("length", [](const model::StringRow& r) { return r.length; })
        .column_text("type", [](const model::StringRow& r) { return r.type; })
        .column_text("type_name", [](const model::StringRow& r) {
            switch (classify_string_encoding(r.encoding)) {
                case StringEncClass::kUtf16: return std::string("utf16");
                case StringEncClass::kUtf32: return std::string("utf32");
                default: return std::string("ascii");
            }
        })
        .column_int("width", [](const model::StringRow& r) {
            switch (classify_string_encoding(r.encoding)) {
                case StringEncClass::kUtf16: return 2;
                case StringEncClass::kUtf32: return 4;
                default: return 1;
            }
        })
        .column_text("width_name", [](const model::StringRow& r) {
            switch (classify_string_encoding(r.encoding)) {
                case StringEncClass::kUtf16: return std::string("2-byte");
                case StringEncClass::kUtf32: return std::string("4-byte");
                default: return std::string("1-byte");
            }
        })
        .column_int("layout", [](const model::StringRow&) { return 0; })
        .column_text("layout_name", [](const model::StringRow&) { return std::string("linear"); })
        .column_text("encoding", [](const model::StringRow& r) { return r.encoding; })
        .column_text("content", [](const model::StringRow& r) { return r.content; })
        .filter_eq_text(
            "content",
            [source](const char* content) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::StringRow> all_rows;
                std::vector<model::StringRow> rows;
                if (source->read_strings(all_rows)) {
                    const std::string needle = content ? content : "";
                    rows.reserve(all_rows.size());
                    for (const auto& row : all_rows) {
                        if (row.content == needle) {
                            rows.push_back(row);
                        }
                    }
                }
                return std::make_unique<OwnedRowIterator<model::StringRow>>(std::move(rows), column_string);
            },
            12.0,
            8.0)
        .filter_eq("address",
            [source](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::StringRow> rows;
                source->read_strings_at(address, rows);
                return std::make_unique<OwnedRowIterator<model::StringRow>>(
                    std::move(rows),
                    column_string);
            }, 1.0, 2.0)
        .index_on("address", [](const model::StringRow& r) { return r.address; })
        .build();
}

inline xsql::CachedTableDef<model::XrefRow> define_xrefs(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::XrefRow>("xrefs")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::XrefRow> rows;
            return source->read_xrefs(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source](std::vector<model::XrefRow>& out) {
            if (!source->read_xrefs(out)) {
                out.clear();
            }
        })
        .column_int64("from_ea", [](const model::XrefRow& r) { return r.from_ea; })
        .column_int64("to_ea", [](const model::XrefRow& r) { return r.to_ea; })
        .column_text("kind", [](const model::XrefRow& r) { return r.kind; })
        .column_int("is_code", [](const model::XrefRow& r) { return r.is_code; })
        .column_int("is_data", [](const model::XrefRow& r) { return r.is_data; })
        .filter_eq_text(
            "kind",
            [source](const char* kind) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::XrefRow> all_rows;
                std::vector<model::XrefRow> rows;
                if (source->read_xrefs(all_rows)) {
                    const std::string needle = kind ? kind : "";
                    rows.reserve(all_rows.size());
                    for (const auto& row : all_rows) {
                        if (row.kind == needle) {
                            rows.push_back(row);
                        }
                    }
                }
                return std::make_unique<OwnedRowIterator<model::XrefRow>>(std::move(rows), column_xref);
            },
            10.0,
            128.0)
        .index_on("from_ea", [](const model::XrefRow& r) { return r.from_ea; })
        .index_on("to_ea", [](const model::XrefRow& r) { return r.to_ea; })
        .build();
}

inline xsql::CachedTableDef<model::CallEdgeRow> define_call_edges(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::CallEdgeRow>("call_edges")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::XrefRow> rows;
            return source->read_xrefs(rows) ? rows.size() : size_t(1000);
        })
        .cache_builder([source](std::vector<model::CallEdgeRow>& out) {
            out = derive_call_edge_rows(source);
        })
        .column_int64("src_func_addr", [](const model::CallEdgeRow& r) { return r.src_func_addr; })
        .column_int64("call_site", [](const model::CallEdgeRow& r) { return r.call_site; })
        .column_int64("dst_addr", [](const model::CallEdgeRow& r) { return r.dst_addr; })
        .column_int64("dst_func_addr", [](const model::CallEdgeRow& r) { return r.dst_func_addr; })
        .column_text("kind", [](const model::CallEdgeRow& r) { return r.kind; })
        .index_on("src_func_addr", [](const model::CallEdgeRow& r) { return r.src_func_addr; })
        .index_on("dst_func_addr", [](const model::CallEdgeRow& r) { return r.dst_func_addr; })
        .index_on("call_site", [](const model::CallEdgeRow& r) { return r.call_site; })
        .build();
}

inline xsql::CachedTableDef<model::FunctionCallRow> define_function_calls(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::FunctionCallRow>("function_calls")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionCallRow> rows;
            return source->read_function_calls(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source](std::vector<model::FunctionCallRow>& out) {
            if (!source->read_function_calls(out)) {
                out.clear();
            }
        })
        .column_int64("src_func_addr", [](const model::FunctionCallRow& r) { return r.src_func_addr; })
        .column_text("src_func_name", [](const model::FunctionCallRow& r) { return r.src_func_name; })
        .column_int64("dst_func_addr", [](const model::FunctionCallRow& r) { return r.dst_func_addr; })
        .column_text("dst_func_name", [](const model::FunctionCallRow& r) { return r.dst_func_name; })
        .column_int64("edge_count", [](const model::FunctionCallRow& r) { return r.edge_count; })
        .index_on("src_func_addr", [](const model::FunctionCallRow& r) { return r.src_func_addr; })
        .index_on("dst_func_addr", [](const model::FunctionCallRow& r) { return r.dst_func_addr; })
        .build();
}

inline xsql::CachedTableDef<model::BlockRow> define_blocks(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::BlockRow>("blocks")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::BlockRow> rows;
            if (source->read_blocks(rows)) {
                return rows.size();
            }
            std::vector<model::FunctionRow> funcs;
            if (source->read_functions(funcs)) {
                return funcs.size();
            }
            return size_t(0);
        })
        .cache_builder([source](std::vector<model::BlockRow>& out) {
            if (!source->read_blocks(out)) {
                out = derive_block_rows(source);
            }
        })
        .column_int64("func_addr", [](const model::BlockRow& r) { return r.func_addr; })
        .column_int64("func_ea", [](const model::BlockRow& r) { return r.func_addr; })
        .column_int64("start_ea", [](const model::BlockRow& r) { return r.start_ea; })
        .column_int64("end_ea", [](const model::BlockRow& r) { return r.end_ea; })
        .column_int64("size", [](const model::BlockRow& r) {
            return r.end_ea > r.start_ea ? (r.end_ea - r.start_ea) : 0;
        })
        .column_int("in_degree", [](const model::BlockRow& r) { return r.in_degree; })
        .column_int("out_degree", [](const model::BlockRow& r) { return r.out_degree; })
        .index_on("func_addr", [](const model::BlockRow& r) { return r.func_addr; })
        .index_on("start_ea", [](const model::BlockRow& r) { return r.start_ea; })
        .build();
}

inline xsql::CachedTableDef<model::CfgEdgeRow> define_cfg_edges(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::CfgEdgeRow>("cfg_edges")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::CfgEdgeRow> rows;
            if (source->read_cfg_edges(rows)) {
                return rows.size();
            }
            std::vector<model::BlockRow> blocks;
            if (source->read_blocks(blocks)) {
                return std::max<size_t>(blocks.size() * 2, 1);
            }
            return size_t(0);
        })
        .cache_builder([source](std::vector<model::CfgEdgeRow>& out) {
            if (!source->read_cfg_edges(out)) {
                out = derive_cfg_edge_rows(source);
            }
        })
        .column_int64("func_addr", [](const model::CfgEdgeRow& r) { return r.func_addr; })
        .column_int64("src_start_ea", [](const model::CfgEdgeRow& r) { return r.src_start_ea; })
        .column_int64("dst_start_ea", [](const model::CfgEdgeRow& r) { return r.dst_start_ea; })
        .column_text("edge_kind", [](const model::CfgEdgeRow& r) { return r.edge_kind; })
        .index_on("func_addr", [](const model::CfgEdgeRow& r) { return r.func_addr; })
        .index_on("src_start_ea", [](const model::CfgEdgeRow& r) { return r.src_start_ea; })
        .index_on("dst_start_ea", [](const model::CfgEdgeRow& r) { return r.dst_start_ea; })
        .build();
}

inline xsql::CachedTableDef<model::LoopRow> define_loops(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::LoopRow>("loops")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(100); })
        .cache_builder([source](std::vector<model::LoopRow>& out) {
            out = derive_loop_rows(source);
        })
        .column_int64("func_addr", [](const model::LoopRow& r) { return r.func_addr; })
        .column_int64("header_ea", [](const model::LoopRow& r) { return r.header_ea; })
        .column_int64("latch_ea", [](const model::LoopRow& r) { return r.latch_ea; })
        .column_int64("start_ea", [](const model::LoopRow& r) { return r.start_ea; })
        .column_int64("end_ea", [](const model::LoopRow& r) { return r.end_ea; })
        .column_int("depth", [](const model::LoopRow& r) { return r.depth; })
        .column_text("loop_kind", [](const model::LoopRow& r) { return r.loop_kind; })
        .column_int64("block_count", [](const model::LoopRow& r) { return r.block_count; })
        .index_on("func_addr", [](const model::LoopRow& r) { return r.func_addr; })
        .build();
}

inline xsql::CachedTableDef<model::SwitchTableRow> define_switch_tables(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::SwitchTableRow>("switch_tables")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(50); })
        .cache_builder([source](std::vector<model::SwitchTableRow>& out) {
            out = derive_switch_table_rows(source);
        })
        .column_int64("func_addr", [](const model::SwitchTableRow& r) { return r.func_addr; })
        .column_int64("instr_ea", [](const model::SwitchTableRow& r) { return r.instr_ea; })
        .column_int64("table_ea", [](const model::SwitchTableRow& r) { return r.table_ea; })
        .column_int64("min_case", [](const model::SwitchTableRow& r) { return r.min_case; })
        .column_int64("max_case", [](const model::SwitchTableRow& r) { return r.max_case; })
        .column_int64("case_count", [](const model::SwitchTableRow& r) { return r.case_count; })
        .column_int64("default_ea", [](const model::SwitchTableRow& r) { return r.default_ea; })
        .index_on("func_addr", [](const model::SwitchTableRow& r) { return r.func_addr; })
        .index_on("instr_ea", [](const model::SwitchTableRow& r) { return r.instr_ea; })
        .build();
}

inline xsql::CachedTableDef<model::DominatorRow> define_dominators(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::DominatorRow>("dominators")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> fns;
            return source->read_functions(fns) ? fns.size() * 3 : size_t(100);
        })
        .cache_builder([source](std::vector<model::DominatorRow>& out) {
            out = derive_dominator_rows(source);
        })
        .column_int64("func_addr", [](const model::DominatorRow& r) { return r.func_addr; })
        .column_int64("node_ea", [](const model::DominatorRow& r) { return r.node_ea; })
        .column_int64("idom_ea", [](const model::DominatorRow& r) { return r.idom_ea; })
        .column_int("depth", [](const model::DominatorRow& r) { return r.depth; })
        .column_int("is_entry", [](const model::DominatorRow& r) { return r.is_entry; })
        .index_on("func_addr", [](const model::DominatorRow& r) { return r.func_addr; })
        .index_on("node_ea", [](const model::DominatorRow& r) { return r.node_ea; })
        .build();
}

inline xsql::CachedTableDef<model::PostDominatorRow> define_post_dominators(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::PostDominatorRow>("post_dominators")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> fns;
            return source->read_functions(fns) ? fns.size() * 3 : size_t(100);
        })
        .cache_builder([source](std::vector<model::PostDominatorRow>& out) {
            out = derive_post_dominator_rows(source);
        })
        .column_int64("func_addr", [](const model::PostDominatorRow& r) { return r.func_addr; })
        .column_int64("node_ea", [](const model::PostDominatorRow& r) { return r.node_ea; })
        .column_int64("ipdom_ea", [](const model::PostDominatorRow& r) { return r.ipdom_ea; })
        .column_int("depth", [](const model::PostDominatorRow& r) { return r.depth; })
        .column_int("is_exit", [](const model::PostDominatorRow& r) { return r.is_exit; })
        .index_on("func_addr", [](const model::PostDominatorRow& r) { return r.func_addr; })
        .index_on("node_ea", [](const model::PostDominatorRow& r) { return r.node_ea; })
        .build();
}

inline xsql::CachedTableDef<model::InstructionRow> define_instructions(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::InstructionRow>("instructions")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::InstructionRow> rows;
            if (source->read_instructions(rows)) {
                return rows.size();
            }
            return size_t(0);
        })
        .cache_builder([source](std::vector<model::InstructionRow>& out) {
            if (!source->read_instructions(out)) {
                out.clear();
            }
        })
        .column_int64("address", [](const model::InstructionRow& r) { return r.address; })
        .column_text("mnemonic", [](const model::InstructionRow& r) { return r.mnemonic; })
        .column_text("operands", [](const model::InstructionRow& r) { return r.operands; })
        .column_text("disasm", [](const model::InstructionRow& r) { return r.disasm; })
        .column_int("size", [](const model::InstructionRow& r) { return r.size; })
        .column_text("bytes", [](const model::InstructionRow& r) { return r.bytes; })
        .filter_eq_text(
            "mnemonic",
            [source](const char* mnemonic) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::InstructionRow> rows;
                std::vector<model::InstructionRow> matched;
                if (source->read_instructions(rows)) {
                    const std::string needle = mnemonic ? mnemonic : "";
                    matched.reserve(rows.size() / 8 + 1);
                    for (const auto& row : rows) {
                        if (row.mnemonic == needle) {
                            matched.push_back(row);
                        }
                    }
                    return std::make_unique<OwnedRowIterator<model::InstructionRow>>(std::move(matched), column_instruction);
                }
                return std::make_unique<OwnedRowIterator<model::InstructionRow>>(std::vector<model::InstructionRow>{}, column_instruction);
            },
            10.0,
            64.0)
        .filter_eq("address",
            [source](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                model::InstructionRow row;
                std::vector<model::InstructionRow> rows;
                if (source->read_instruction_at(address, row)) {
                    rows.push_back(std::move(row));
                }
                return std::make_unique<OwnedRowIterator<model::InstructionRow>>(
                    std::move(rows),
                    column_instruction);
            }, 1.0, 1.0)
        .index_on("address", [](const model::InstructionRow& r) { return r.address; })
        .build();
}

inline void column_comment(xsql::FunctionContext& ctx, int col, const model::CommentRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_text(r.comment); return;
        case 2: ctx.result_int64(r.repeatable); return;
        case 3: ctx.result_text(r.source); return;
        default: ctx.result_null(); return;
    }
}

inline xsql::CachedTableDef<model::CommentRow> define_comments(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::CommentRow>("comments")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::CommentRow> rows;
            return source->read_comments(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source](std::vector<model::CommentRow>& out) {
            if (!source->read_comments(out)) {
                out.clear();
            }
        })
        .column_int64("address", [](const model::CommentRow& r) { return r.address; })
        .column_text_rw(
            "comment",
            [](const model::CommentRow& r) { return r.comment; },
            [source](model::CommentRow& row, const char* text) {
                const std::string next = text ? text : "";
                if (row.comment == next) {
                    return true;
                }
                if (!row.source.empty() &&
                    source->set_comment_by_kind(row.address, next, row.source)) {
                    row.comment = next;
                    return true;
                }
                if (!source->set_comment(row.address, next, row.repeatable != 0)) {
                    report_write_error(
                        source,
                        "UPDATE comments.comment failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.comment = next;
                return true;
            })
        .column_int64_rw(
            "repeatable",
            [](const model::CommentRow& r) { return r.repeatable; },
            [source](model::CommentRow& row, std::int64_t value) {
                const int next = value != 0 ? 1 : 0;
                if (row.repeatable == next) {
                    return true;
                }
                if (!source->set_comment(row.address, row.comment, next != 0)) {
                    report_write_error(
                        source,
                        "UPDATE comments.repeatable failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.repeatable = next;
                return true;
            })
        .column_text_rw(
            "source",
            [](const model::CommentRow& r) { return r.source; },
            [source](model::CommentRow& row, const char* text) {
                const std::string next = text ? text : "eol";
                if (row.source == next) {
                    return true;
                }
                if (!source->set_comment_by_kind(row.address, row.comment, next)) {
                    report_write_error(
                        source,
                        "UPDATE comments.source failed at 0x" + std::to_string(row.address));
                    return false;
                }
                // Delete old comment at previous kind
                source->delete_comment_by_kind(row.address, row.source);
                row.source = next;
                row.repeatable = (next == "repeatable") ? 1 : 0;
                return true;
            })
        .deletable([source](model::CommentRow& row) {
            if (source->delete_comment_by_kind(row.address, row.source)) {
                return true;
            }
            return source->delete_comment(row.address, row.repeatable != 0);
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            const auto address = arg_int64_opt(argc, argv, 0);
            if (!address) {
                xsql::set_vtab_error("INSERT INTO comments requires address");
                return false;
            }

            const auto comment = arg_text_opt(argc, argv, 1);
            const bool repeatable = arg_int64_opt(argc, argv, 2).value_or(0) != 0;
            const auto source_kind = arg_text_opt(argc, argv, 3);
            return comment_insert_common(source, "comments", *address, comment, source_kind, repeatable);
        })
        .row_lookup([source](model::CommentRow& row, std::int64_t raw_rowid) {
            std::int64_t address = 0;
            size_t slot = 0;
            if (!decode_address_slot_rowid(raw_rowid, address, slot)) {
                return false;
            }
            std::vector<model::CommentRow> rows;
            if (!source->read_comments_at(address, rows) || slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .filter_eq("address",
            [source](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::CommentRow> rows;
                source->read_comments_at(address, rows);
                std::vector<std::pair<std::int64_t, model::CommentRow>> indexed;
                indexed.reserve(rows.size());
                for (size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(encode_address_slot_rowid(address, i), std::move(rows[i]));
                }
                return std::make_unique<IndexedOwnedRowIterator<model::CommentRow>>(
                    std::move(indexed),
                    column_comment);
            }, 1.0, 1.0)
        .build();
}

inline xsql::CachedTableDef<model::DataItemRow> define_data_items(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::DataItemRow>("data_items")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::DataItemRow> rows;
            return source->read_data_items(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source](std::vector<model::DataItemRow>& out) {
            if (!source->read_data_items(out)) {
                out = derive_data_item_rows(source);
            }
        })
        .column_int64("address", [](const model::DataItemRow& r) { return r.address; })
        .column_text_rw(
            "name",
            [](const model::DataItemRow& r) { return r.name; },
            [source](model::DataItemRow& row, const char* name) {
                const std::string next = name ? name : "";
                if (row.name == next) {
                    return true;
                }
                if (!source->rename_data_item(row.address, next)) {
                    xsql::set_vtab_error("UPDATE data_items.name failed: rename_data_item at 0x" +
                        std::to_string(row.address));
                    return false;
                }
                row.name = next;
                return true;
            })
        .column_text_rw(
            "data_type",
            [](const model::DataItemRow& r) { return r.data_type; },
            [source](model::DataItemRow& row, const char* type_name) {
                const std::string next = type_name ? type_name : "";
                if (row.data_type == next) {
                    return true;
                }
                if (!source->set_data_item_type(row.address, next)) {
                    xsql::set_vtab_error("UPDATE data_items.data_type failed: set_data_item_type at 0x" +
                        std::to_string(row.address));
                    return false;
                }
                row.data_type = next;
                return true;
            })
        .column_int64("size", [](const model::DataItemRow& r) { return r.size; })
        .column_text("value_repr", [](const model::DataItemRow& r) { return r.value_repr; })
        .column_text("segment_name", [](const model::DataItemRow& r) { return r.segment_name; })
        .column_int("is_string", [](const model::DataItemRow& r) { return r.is_string; })
        .column_int("is_initialized", [](const model::DataItemRow& r) { return r.is_initialized; })
        .deletable([source](model::DataItemRow& row) {
            return source->delete_data_item(row.address);
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            const auto address = arg_int64_opt(argc, argv, 0);
            const auto data_type = arg_text_opt(argc, argv, 2);
            const auto name = arg_text_opt(argc, argv, 1);
            if (!address || !data_type || data_type->empty()) {
                xsql::set_vtab_error("INSERT INTO data_items requires address and data_type");
                return false;
            }
            if (!source->create_data_item(*address, *data_type, name.value_or(""))) {
                xsql::set_vtab_error("INSERT INTO data_items failed: create_data_item at 0x" +
                    std::to_string(*address));
                return false;
            }
            return true;
        })
        .row_lookup([source](model::DataItemRow& row, std::int64_t raw_rowid) {
            std::int64_t address = 0;
            size_t slot = 0;
            if (!decode_address_rowid(raw_rowid, address, slot)) {
                return false;
            }
            std::vector<model::DataItemRow> rows;
            if (!source->read_data_items_at(address, rows) || slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .filter_eq("address",
            [source](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::DataItemRow> rows;
                source->read_data_items_at(address, rows);
                std::vector<std::pair<std::int64_t, model::DataItemRow>> indexed;
                indexed.reserve(rows.size());
                for (size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(encode_address_rowid(address, i), std::move(rows[i]));
                }
                return std::make_unique<IndexedOwnedRowIterator<model::DataItemRow>>(
                    std::move(indexed),
                    column_data_item);
            }, 1.0, 2.0)
        .build();
}

inline xsql::CachedTableDef<model::FunctionLocalRow> define_function_locals(
    const std::shared_ptr<Source>& source,
    const std::shared_ptr<QueryScopeState>& query_scope) {
    // Same O(1) per-function decompilation pattern as define_decomp_lvars.
    constexpr std::int64_t kLocalsPerFunction = 0x10000;

    return xsql::cached_table<model::FunctionLocalRow>("function_locals")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> fns;
            return source->read_functions(fns) ? fns.size() * 3 : size_t(100);
        })
        .cache_builder([source, query_scope](std::vector<model::FunctionLocalRow>& out) {
            auto indexed = derive_indexed_function_local_rows(source);
            out.clear();
            out.reserve(indexed.size());
            for (const auto& entry : indexed) {
                out.push_back(entry.second);
            }
            query_scope->function_local_rows.store(std::move(indexed));
        })
        .column_int64("func_addr", [](const model::FunctionLocalRow& r) { return r.func_addr; })
        .column_text("local_id", [](const model::FunctionLocalRow& r) { return r.local_id; })
        .column_text_rw(
            "name",
            [](const model::FunctionLocalRow& r) { return r.name; },
            [source](model::FunctionLocalRow& row, const char* text) {
                const std::string next = text ? text : "";
                if (row.name == next) {
                    return true;
                }
                if (!source->rename_decomp_local(row.func_addr, row.local_id, next)) {
                    report_write_error(source,
                        "UPDATE function_locals.name failed for local_id '" + row.local_id +
                        "' at 0x" + std::to_string(row.func_addr));
                    return false;
                }
                row.name = next;
                return true;
            })
        .column_text_rw(
            "local_type",
            [](const model::FunctionLocalRow& r) { return r.local_type; },
            [source](model::FunctionLocalRow& row, const char* text) {
                const std::string next = text ? text : "";
                if (row.local_type == next) {
                    return true;
                }
                if (!source->set_decomp_local_type(row.func_addr, row.local_id, next)) {
                    report_write_error(source,
                        "UPDATE function_locals.local_type failed for local_id '" + row.local_id +
                        "' at 0x" + std::to_string(row.func_addr));
                    return false;
                }
                row.local_type = next;
                return true;
            })
        .column_text("storage", [](const model::FunctionLocalRow& r) { return r.storage; })
        .column_int64("stack_offset", [](const model::FunctionLocalRow& r) { return r.stack_offset; })
        .column_int64("size", [](const model::FunctionLocalRow& r) { return r.size; })
        .row_lookup([source, query_scope, kLocalsPerFunction](model::FunctionLocalRow& row, std::int64_t raw_rowid) {
            if (raw_rowid < 0) {
                return false;
            }
            if (query_scope->function_local_rows.lookup(raw_rowid, row)) {
                return true;
            }
            const std::int64_t func_addr =
                raw_rowid >= 0 ? (raw_rowid / kLocalsPerFunction) : raw_rowid;
            const auto local_index = static_cast<size_t>(raw_rowid % kLocalsPerFunction);
            auto rows = derive_function_local_rows_for(source, func_addr);
            if (local_index < rows.size()) {
                row = std::move(rows[local_index]);
                return true;
            }
            return false;
        })
        .filter_eq("func_addr",
            [source, query_scope, kLocalsPerFunction](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                auto rows = derive_function_local_rows_for(source, func_addr);
                std::vector<std::pair<std::int64_t, model::FunctionLocalRow>> indexed;
                indexed.reserve(rows.size());
                for (std::int64_t i = 0; i < static_cast<std::int64_t>(rows.size()); ++i) {
                    indexed.emplace_back(func_addr * kLocalsPerFunction + i, std::move(rows[i]));
                }
                query_scope->function_local_rows.store(indexed);
                return std::make_unique<IndexedOwnedRowIterator<model::FunctionLocalRow>>(
                    std::move(indexed),
                    column_function_local);
            }, 1.0, 4.0)
        .build();
}

inline xsql::CachedTableDef<model::StackVarRow> define_stack_vars(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::StackVarRow>("stack_vars")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> fns;
            return source->read_functions(fns) ? fns.size() * 3 : size_t(100);
        })
        .cache_builder([source](std::vector<model::StackVarRow>& out) {
            out = derive_stack_var_rows(source);
        })
        .column_int64("func_addr", [](const model::StackVarRow& r) { return r.func_addr; })
        .column_text("var_id", [](const model::StackVarRow& r) { return r.var_id; })
        .column_text("name", [](const model::StackVarRow& r) { return r.name; })
        .column_text("var_type", [](const model::StackVarRow& r) { return r.var_type; })
        .column_int64("stack_offset", [](const model::StackVarRow& r) { return r.stack_offset; })
        .column_int64("size", [](const model::StackVarRow& r) { return r.size; })
        .column_int("is_param", [](const model::StackVarRow& r) { return r.is_param; })
        .index_on("func_addr", [](const model::StackVarRow& r) { return r.func_addr; })
        .index_on("stack_offset", [](const model::StackVarRow& r) { return r.stack_offset; })
        .build();
}

inline xsql::CachedTableDef<model::RegisterVarRow> define_register_vars(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::RegisterVarRow>("register_vars")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> fns;
            return source->read_functions(fns) ? fns.size() * 3 : size_t(100);
        })
        .cache_builder([source](std::vector<model::RegisterVarRow>& out) {
            out = derive_register_var_rows(source);
        })
        .column_int64("func_addr", [](const model::RegisterVarRow& r) { return r.func_addr; })
        .column_text("var_id", [](const model::RegisterVarRow& r) { return r.var_id; })
        .column_text("name", [](const model::RegisterVarRow& r) { return r.name; })
        .column_text("var_type", [](const model::RegisterVarRow& r) { return r.var_type; })
        .column_text("reg_name", [](const model::RegisterVarRow& r) { return r.reg_name; })
        .column_int64("size", [](const model::RegisterVarRow& r) { return r.size; })
        .column_int("is_param", [](const model::RegisterVarRow& r) { return r.is_param; })
        .index_on("func_addr", [](const model::RegisterVarRow& r) { return r.func_addr; })
        .build();
}

inline xsql::CachedTableDef<model::FunctionChunkRow> define_function_chunks(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::FunctionChunkRow>("function_chunks")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> fns;
            return source->read_functions(fns) ? fns.size() : size_t(100);
        })
        .cache_builder([source](std::vector<model::FunctionChunkRow>& out) {
            out = derive_function_chunk_rows(source);
        })
        .column_int64("func_addr", [](const model::FunctionChunkRow& r) { return r.func_addr; })
        .column_text("chunk_id", [](const model::FunctionChunkRow& r) { return r.chunk_id; })
        .column_int64("start_ea", [](const model::FunctionChunkRow& r) { return r.start_ea; })
        .column_int64("end_ea", [](const model::FunctionChunkRow& r) { return r.end_ea; })
        .column_text("chunk_kind", [](const model::FunctionChunkRow& r) { return r.chunk_kind; })
        .column_int("is_primary", [](const model::FunctionChunkRow& r) { return r.is_primary; })
        .index_on("func_addr", [](const model::FunctionChunkRow& r) { return r.func_addr; })
        .index_on("start_ea", [](const model::FunctionChunkRow& r) { return r.start_ea; })
        .build();
}

inline xsql::CachedTableDef<model::TailCallRow> define_tail_calls(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::TailCallRow>("tail_calls")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(50); })
        .cache_builder([source](std::vector<model::TailCallRow>& out) {
            out = derive_tail_call_rows(source);
        })
        .column_int64("src_func_addr", [](const model::TailCallRow& r) { return r.src_func_addr; })
        .column_int64("call_site", [](const model::TailCallRow& r) { return r.call_site; })
        .column_int64("dst_addr", [](const model::TailCallRow& r) { return r.dst_addr; })
        .column_int64("dst_func_addr", [](const model::TailCallRow& r) { return r.dst_func_addr; })
        .column_text("tail_kind", [](const model::TailCallRow& r) { return r.tail_kind; })
        .index_on("src_func_addr", [](const model::TailCallRow& r) { return r.src_func_addr; })
        .index_on("dst_func_addr", [](const model::TailCallRow& r) { return r.dst_func_addr; })
        .index_on("call_site", [](const model::TailCallRow& r) { return r.call_site; })
        .build();
}

inline xsql::CachedTableDef<model::ProgramOptionRow> define_program_options(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::ProgramOptionRow>("program_options")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(20); })
        .cache_builder([source](std::vector<model::ProgramOptionRow>& out) {
            out = derive_program_option_rows(source);
        })
        .column_text("option_key", [](const model::ProgramOptionRow& r) { return r.option_key; })
        .column_text("option_value", [](const model::ProgramOptionRow& r) { return r.option_value; })
        .column_text("value_type", [](const model::ProgramOptionRow& r) { return r.value_type; })
        .column_text("option_scope", [](const model::ProgramOptionRow& r) { return r.option_scope; })
        .build();
}

inline xsql::CachedTableDef<model::AnalysisPassRow> define_analysis_passes(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::AnalysisPassRow>("analysis_passes")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(10); })
        .cache_builder([source](std::vector<model::AnalysisPassRow>& out) {
            out = derive_analysis_pass_rows(source);
        })
        .column_int64("pass_id", [](const model::AnalysisPassRow& r) { return r.pass_id; })
        .column_text("pass_name", [](const model::AnalysisPassRow& r) { return r.pass_name; })
        .column_text("status", [](const model::AnalysisPassRow& r) { return r.status; })
        .column_int64("started_unix", [](const model::AnalysisPassRow& r) { return r.started_unix; })
        .column_int64("ended_unix", [](const model::AnalysisPassRow& r) { return r.ended_unix; })
        .column_text("notes", [](const model::AnalysisPassRow& r) { return r.notes; })
        .index_on("pass_id", [](const model::AnalysisPassRow& r) { return r.pass_id; })
        .build();
}

inline xsql::CachedTableDef<model::TransactionRow> define_transactions(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::TransactionRow>("transactions")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(10); })
        .cache_builder([source](std::vector<model::TransactionRow>& out) {
            out = derive_transaction_rows(source);
        })
        .column_int64("tx_id", [](const model::TransactionRow& r) { return r.tx_id; })
        .column_text("tx_name", [](const model::TransactionRow& r) { return r.tx_name; })
        .column_text("tx_kind", [](const model::TransactionRow& r) { return r.tx_kind; })
        .column_int64("start_revision", [](const model::TransactionRow& r) { return r.start_revision; })
        .column_int64("end_revision", [](const model::TransactionRow& r) { return r.end_revision; })
        .column_int("committed", [](const model::TransactionRow& r) { return r.committed; })
        .index_on("tx_id", [](const model::TransactionRow& r) { return r.tx_id; })
        .build();
}

inline xsql::CachedTableDef<model::ProjectPropertyRow> define_project_properties(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::ProjectPropertyRow>("project_properties")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(20); })
        .cache_builder([source](std::vector<model::ProjectPropertyRow>& out) {
            out = derive_project_property_rows(source);
        })
        .column_text("property_key", [](const model::ProjectPropertyRow& r) { return r.property_key; })
        .column_text("property_value", [](const model::ProjectPropertyRow& r) { return r.property_value; })
        .column_text("property_scope", [](const model::ProjectPropertyRow& r) { return r.property_scope; })
        .build();
}

inline xsql::CachedTableDef<model::RelocationRow> define_relocations(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::RelocationRow>("relocations")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(200); })
        .cache_builder([source](std::vector<model::RelocationRow>& out) {
            out = derive_relocation_rows(source);
        })
        .column_int64("address", [](const model::RelocationRow& r) { return r.address; })
        .column_int64("target_addr", [](const model::RelocationRow& r) { return r.target_addr; })
        .column_text("reloc_type", [](const model::RelocationRow& r) { return r.reloc_type; })
        .column_int64("width", [](const model::RelocationRow& r) { return r.width; })
        .column_text("symbol_name", [](const model::RelocationRow& r) { return r.symbol_name; })
        .index_on("address", [](const model::RelocationRow& r) { return r.address; })
        .index_on("target_addr", [](const model::RelocationRow& r) { return r.target_addr; })
        .build();
}

inline xsql::CachedTableDef<model::ConstantRow> define_constants(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::ConstantRow>("constants")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(500); })
        .cache_builder([source](std::vector<model::ConstantRow>& out) {
            out = derive_constant_rows(source);
        })
        .column_int64("address", [](const model::ConstantRow& r) { return r.address; })
        .column_int64("func_addr", [](const model::ConstantRow& r) { return r.func_addr; })
        .column_int64("value", [](const model::ConstantRow& r) { return r.value; })
        .column_int64("width", [](const model::ConstantRow& r) { return r.width; })
        .column_text("repr", [](const model::ConstantRow& r) { return r.repr; })
        .column_text("source_kind", [](const model::ConstantRow& r) { return r.source_kind; })
        .index_on("address", [](const model::ConstantRow& r) { return r.address; })
        .index_on("func_addr", [](const model::ConstantRow& r) { return r.func_addr; })
        .index_on("value", [](const model::ConstantRow& r) { return r.value; })
        .build();
}

inline xsql::CachedTableDef<model::EquateRow> define_equates(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::EquateRow>("equates")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(100); })
        .cache_builder([source](std::vector<model::EquateRow>& out) {
            out = derive_equate_rows(source);
        })
        .column_text("equate_id", [](const model::EquateRow& r) { return r.equate_id; })
        .column_text("name", [](const model::EquateRow& r) { return r.name; })
        .column_int64("value", [](const model::EquateRow& r) { return r.value; })
        .column_int64("width", [](const model::EquateRow& r) { return r.width; })
        .column_text("domain", [](const model::EquateRow& r) { return r.domain; })
        .index_on("value", [](const model::EquateRow& r) { return r.value; })
        .build();
}

inline xsql::CachedTableDef<model::TypeRow> define_types(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::TypeRow>("types")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::TypeRow> rows;
            if (source->read_types(rows)) {
                return rows.size();
            }
            return derive_type_rows(source).size();
        })
        .cache_builder([source](std::vector<model::TypeRow>& out) {
            if (!source->read_types(out)) {
                out = derive_type_rows(source);
            }
        })
        .column_int64("ordinal", [](const model::TypeRow& r) {
            return stable_type_ordinal(r.type_id);
        })
        .column_text("type_id", [](const model::TypeRow& r) { return r.type_id; })
        .column_text_rw(
            "name",
            [](const model::TypeRow& r) { return r.name; },
            [source](model::TypeRow& row, const char* name) {
                return source->rename_type(row.type_id, name ? name : "");
            })
        .column_text("kind", [](const model::TypeRow& r) { return r.kind; })
        .column_int64("size", [](const model::TypeRow& r) { return r.size; })
        .column_int64("alignment", [](const model::TypeRow& r) {
            if (r.size <= 0) {
                return std::int64_t(0);
            }
            if (r.size >= 8) {
                return std::int64_t(8);
            }
            return r.size;
        })
        .column_int("is_struct", [](const model::TypeRow& r) { return lower_copy(r.kind) == "struct" ? 1 : 0; })
        .column_int("is_union", [](const model::TypeRow& r) { return lower_copy(r.kind) == "union" ? 1 : 0; })
        .column_int("is_enum", [](const model::TypeRow& r) { return lower_copy(r.kind) == "enum" ? 1 : 0; })
        .column_int("is_typedef", [](const model::TypeRow& r) {
            const auto k = lower_copy(r.kind);
            return (k == "typedef" || k == "alias") ? 1 : 0;
        })
        .column_int("is_func", [](const model::TypeRow& r) {
            const auto k = lower_copy(r.kind);
            return (k == "func" || k == "function") ? 1 : 0;
        })
        .column_int("is_ptr", [](const model::TypeRow& r) {
            const auto k = lower_copy(r.kind);
            return (k == "ptr" || r.name.find('*') != std::string::npos || r.declaration.find('*') != std::string::npos)
                ? 1
                : 0;
        })
        .column_int("is_array", [](const model::TypeRow& r) {
            const auto k = lower_copy(r.kind);
            return (k == "array" || r.name.find('[') != std::string::npos || r.declaration.find('[') != std::string::npos)
                ? 1
                : 0;
        })
        .column_text("definition", [](const model::TypeRow& r) { return r.declaration; })
        .column_text("resolved", [](const model::TypeRow& r) { return r.declaration; })
        .column_text("declaration", [](const model::TypeRow& r) { return r.declaration; })
        .deletable([source](model::TypeRow& row) {
            return source->delete_type(row.type_id);
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            const std::string name = arg_text_or(argc, argv, 2);
            const std::string kind = arg_text_or(argc, argv, 3);
            const std::int64_t size = arg_int64_opt(argc, argv, 4).value_or(0);
            std::string declaration = arg_text_or(argc, argv, 15);
            if (declaration.empty()) {
                declaration = arg_text_or(argc, argv, 13);
            }
            if (name.empty() || kind.empty()) {
                xsql::set_vtab_error("INSERT INTO types requires name and kind");
                return false;
            }
            if (!source->create_type(name, kind, size, declaration)) {
                xsql::set_vtab_error("INSERT INTO types failed for '" + name + "'");
                return false;
            }
            return true;
        })
        .build();
}

inline xsql::CachedTableDef<model::TypeMemberRow> define_type_members(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::TypeMemberRow>("type_members")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::TypeMemberRow> rows;
            if (source->read_type_members(rows)) {
                return rows.size();
            }
            return derive_type_member_rows(source).size();
        })
        .cache_builder([source](std::vector<model::TypeMemberRow>& out) {
            if (!source->read_type_members(out)) {
                out = derive_type_member_rows(source);
            }
        })
        .column_text("parent_type_id", [](const model::TypeMemberRow& r) { return r.parent_type_id; })
        .column_text("parent_type_name", [](const model::TypeMemberRow& r) { return r.parent_type_name; })
        .column_text_rw(
            "member_name",
            [](const model::TypeMemberRow& r) { return r.member_name; },
            [source](model::TypeMemberRow& row, const char* name) {
                if (!source->rename_type_member(row.parent_type_id, row.ordinal, name ? name : "")) {
                    xsql::set_vtab_error("UPDATE type_members.member_name failed: rename_type_member for type " +
                        row.parent_type_name);
                    return false;
                }
                return true;
            })
        .column_text_rw(
            "member_type",
            [](const model::TypeMemberRow& r) { return r.member_type; },
            [source](model::TypeMemberRow& row, const char* type_name) {
                const std::string next = type_name ? type_name : "";
                if (row.member_type == next) {
                    return true;
                }
                if (!source->set_type_member_type(row.parent_type_id, row.ordinal, next)) {
                    xsql::set_vtab_error("UPDATE type_members.member_type failed: set_type_member_type for type " +
                        row.parent_type_name);
                    return false;
                }
                row.member_type = next;
                return true;
            })
        .column_int64("offset", [](const model::TypeMemberRow& r) { return r.offset; })
        .column_int64("size", [](const model::TypeMemberRow& r) { return r.size; })
        .column_int64("ordinal", [](const model::TypeMemberRow& r) { return r.ordinal; })
        .column_text_rw(
            "comment",
            [](const model::TypeMemberRow& r) { return r.comment; },
            [source](model::TypeMemberRow& row, const char* text) {
                const std::string next = text ? text : "";
                if (row.comment == next) {
                    return true;
                }
                if (!source->set_type_member_comment(row.parent_type_id, row.ordinal, next)) {
                    xsql::set_vtab_error("UPDATE type_members.comment failed: set_type_member_comment for type " +
                        row.parent_type_name);
                    return false;
                }
                row.comment = next;
                return true;
            })
        .deletable([source](model::TypeMemberRow& row) {
            return source->delete_type_member(row.parent_type_id, row.ordinal);
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            const std::string parent_type_id = arg_text_or(argc, argv, 0);
            const std::string member_name = arg_text_or(argc, argv, 2);
            const std::string member_type = arg_text_or(argc, argv, 3);
            const std::int64_t size = arg_int64_opt(argc, argv, 5).value_or(1);
            if (parent_type_id.empty() || member_name.empty() || member_type.empty()) {
                xsql::set_vtab_error(
                    "INSERT INTO type_members requires parent_type_id, member_name, and member_type");
                return false;
            }
            if (!source->add_type_member(parent_type_id, member_name, member_type, size)) {
                xsql::set_vtab_error(
                    "INSERT INTO type_members failed for type '" + parent_type_id + "'");
                return false;
            }
            return true;
        })
        .build();
}

inline xsql::CachedTableDef<model::TypeEnumRow> define_type_enums(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::TypeEnumRow>("type_enums")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::TypeEnumRow> rows;
            if (source->read_type_enums(rows)) {
                return rows.size();
            }
            return derive_type_enum_rows(source).size();
        })
        .cache_builder([source](std::vector<model::TypeEnumRow>& out) {
            if (!source->read_type_enums(out)) {
                out = derive_type_enum_rows(source);
            }
        })
        .column_text("type_id", [](const model::TypeEnumRow& r) { return r.type_id; })
        .column_text_rw(
            "name",
            [](const model::TypeEnumRow& r) { return r.name; },
            [source](model::TypeEnumRow& row, const char* name) {
                if (!source->rename_type(row.type_id, name ? name : "")) {
                    xsql::set_vtab_error("UPDATE type_enums.name failed: rename_type for enum " +
                        row.name);
                    return false;
                }
                return true;
            })
        .column_int64("width", [](const model::TypeEnumRow& r) { return r.width; })
        .column_int("is_signed", [](const model::TypeEnumRow& r) { return r.is_signed; })
        .column_text("declaration", [](const model::TypeEnumRow& r) { return r.declaration; })
        .deletable([source](model::TypeEnumRow& row) {
            return source->delete_type_enum(row.type_id);
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            const std::string name = arg_text_or(argc, argv, 1);
            const std::int64_t width = arg_int64_opt(argc, argv, 2).value_or(4);
            const bool is_signed = arg_int64_opt(argc, argv, 3).value_or(0) != 0;
            if (name.empty()) {
                xsql::set_vtab_error("INSERT INTO type_enums requires name");
                return false;
            }
            if (!source->create_type_enum(name, width, is_signed)) {
                xsql::set_vtab_error("INSERT INTO type_enums failed for '" + name + "'");
                return false;
            }
            return true;
        })
        .build();
}

inline xsql::CachedTableDef<model::TypeEnumMemberRow> define_type_enum_members(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::TypeEnumMemberRow>("type_enum_members")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::TypeEnumMemberRow> rows;
            if (source->read_type_enum_members(rows)) {
                return rows.size();
            }
            return derive_type_enum_member_rows(source).size();
        })
        .cache_builder([source](std::vector<model::TypeEnumMemberRow>& out) {
            if (!source->read_type_enum_members(out)) {
                out = derive_type_enum_member_rows(source);
            }
        })
        .column_text("type_id", [](const model::TypeEnumMemberRow& r) { return r.type_id; })
        .column_text_rw(
            "name",
            [](const model::TypeEnumMemberRow& r) { return r.name; },
            [source](model::TypeEnumMemberRow& row, const char* name) {
                const std::string next = name ? name : "";
                if (row.name == next) {
                    return true;
                }
                if (!source->rename_type_enum_member(row.type_id, row.ordinal, next)) {
                    xsql::set_vtab_error("UPDATE type_enum_members.name failed: rename_type_enum_member");
                    return false;
                }
                row.name = next;
                return true;
            })
        .column_int64_rw(
            "value",
            [](const model::TypeEnumMemberRow& r) { return r.value; },
            [source](model::TypeEnumMemberRow& row, std::int64_t value) {
                if (row.value == value) {
                    return true;
                }
                if (!source->set_type_enum_member_value(row.type_id, row.ordinal, value)) {
                    xsql::set_vtab_error("UPDATE type_enum_members.value failed: set_type_enum_member_value");
                    return false;
                }
                row.value = value;
                return true;
            })
        .column_int64("ordinal", [](const model::TypeEnumMemberRow& r) { return r.ordinal; })
        .column_text_rw(
            "comment",
            [](const model::TypeEnumMemberRow& r) { return r.comment; },
            [source](model::TypeEnumMemberRow& row, const char* text) {
                const std::string next = text ? text : "";
                if (row.comment == next) {
                    return true;
                }
                if (!source->set_type_enum_member_comment(row.type_id, row.ordinal, next)) {
                    xsql::set_vtab_error("UPDATE type_enum_members.comment failed: set_type_enum_member_comment");
                    return false;
                }
                row.comment = next;
                return true;
            })
        .deletable([source](model::TypeEnumMemberRow& row) {
            return source->delete_type_enum_member(row.type_id, row.ordinal);
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            const std::string type_id = arg_text_or(argc, argv, 0);
            const std::string name = arg_text_or(argc, argv, 1);
            const auto value = arg_int64_opt(argc, argv, 2);
            if (type_id.empty() || name.empty() || !value) {
                xsql::set_vtab_error("INSERT INTO type_enum_members requires type_id, name, and value");
                return false;
            }
            if (!source->add_type_enum_member(type_id, name, *value)) {
                xsql::set_vtab_error(
                    "INSERT INTO type_enum_members failed for enum '" + type_id + "'");
                return false;
            }
            return true;
        })
        .build();
}

inline xsql::CachedTableDef<model::TypeUnionRow> define_type_unions(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::TypeUnionRow>("type_unions")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::TypeUnionRow> rows;
            if (source->read_type_unions(rows)) {
                return rows.size();
            }
            return derive_type_union_rows(source).size();
        })
        .cache_builder([source](std::vector<model::TypeUnionRow>& out) {
            if (!source->read_type_unions(out)) {
                out = derive_type_union_rows(source);
            }
        })
        .column_text("type_id", [](const model::TypeUnionRow& r) { return r.type_id; })
        .column_text_rw(
            "name",
            [](const model::TypeUnionRow& r) { return r.name; },
            [source](model::TypeUnionRow& row, const char* name) {
                if (!source->rename_type(row.type_id, name ? name : "")) {
                    xsql::set_vtab_error("UPDATE type_unions.name failed: rename_type for union " +
                        row.name);
                    return false;
                }
                return true;
            })
        .column_int64("size", [](const model::TypeUnionRow& r) { return r.size; })
        .column_text("declaration", [](const model::TypeUnionRow& r) { return r.declaration; })
        .deletable([source](model::TypeUnionRow& row) {
            return source->delete_type_union(row.type_id);
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            const std::string name = arg_text_or(argc, argv, 1);
            const std::int64_t size = arg_int64_opt(argc, argv, 2).value_or(0);
            const std::string declaration = arg_text_or(argc, argv, 3);
            if (name.empty()) {
                xsql::set_vtab_error("INSERT INTO type_unions requires name");
                return false;
            }
            if (!source->create_type_union(name, size, declaration)) {
                xsql::set_vtab_error("INSERT INTO type_unions failed for '" + name + "'");
                return false;
            }
            return true;
        })
        .build();
}

inline xsql::CachedTableDef<model::TypeAliasRow> define_type_aliases(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::TypeAliasRow>("type_aliases")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::TypeAliasRow> rows;
            if (source->read_type_aliases(rows)) {
                return rows.size();
            }
            return derive_type_alias_rows(source).size();
        })
        .cache_builder([source](std::vector<model::TypeAliasRow>& out) {
            if (!source->read_type_aliases(out)) {
                out = derive_type_alias_rows(source);
            }
        })
        .column_text("type_id", [](const model::TypeAliasRow& r) { return r.type_id; })
        .column_text_rw(
            "name",
            [](const model::TypeAliasRow& r) { return r.name; },
            [source](model::TypeAliasRow& row, const char* name) {
                if (!source->rename_type(row.type_id, name ? name : "")) {
                    xsql::set_vtab_error("UPDATE type_aliases.name failed: rename_type for typedef " +
                        row.name);
                    return false;
                }
                return true;
            })
        .column_text_rw(
            "target_type",
            [](const model::TypeAliasRow& r) { return r.target_type; },
            [source](model::TypeAliasRow& row, const char* target_type) {
                const std::string next = target_type ? target_type : "";
                if (row.target_type == next) {
                    return true;
                }
                if (!source->set_type_alias_target(row.type_id, next)) {
                    xsql::set_vtab_error("UPDATE type_aliases.target_type failed: set_type_alias_target for " +
                        row.name);
                    return false;
                }
                row.target_type = next;
                row.declaration = "typedef " + next + " " + row.name;
                return true;
            })
        .column_text("declaration", [](const model::TypeAliasRow& r) { return r.declaration; })
        .deletable([source](model::TypeAliasRow& row) {
            return source->delete_type_alias(row.type_id);
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            const std::string name = arg_text_or(argc, argv, 1);
            const std::string target_type = arg_text_or(argc, argv, 2);
            if (name.empty() || target_type.empty()) {
                xsql::set_vtab_error("INSERT INTO type_aliases requires name and target_type");
                return false;
            }
            if (!source->create_type_alias(name, target_type)) {
                xsql::set_vtab_error("INSERT INTO type_aliases failed for '" + name + "'");
                return false;
            }
            return true;
        })
        .build();
}

inline xsql::CachedTableDef<model::SignatureRow> define_signatures(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::SignatureRow>("signatures")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::SignatureRow> rows;
            if (source->read_signatures(rows)) {
                return rows.size();
            }
            return derive_signature_rows(source).size();
        })
        .cache_builder([source](std::vector<model::SignatureRow>& out) {
            if (!source->read_signatures(out)) {
                out = derive_signature_rows(source);
            }
        })
        .column_text("sig_id", [](const model::SignatureRow& r) { return r.sig_id; })
        .column_text("owner_kind", [](const model::SignatureRow& r) { return r.owner_kind; })
        .column_int64("owner_addr", [](const model::SignatureRow& r) { return r.owner_addr; })
        .column_text_rw(
            "name",
            [](const model::SignatureRow& r) { return r.name; },
            [source](model::SignatureRow& row, const char* name) {
                if (row.owner_kind != "function") {
                    xsql::set_vtab_error("UPDATE signatures.name failed: only function signatures can be renamed");
                    return false;
                }
                const std::string next = name ? name : "";
                if (row.name == next) {
                    return true;
                }
                if (!source->rename_function(row.owner_addr, next)) {
                    report_write_error(
                        source,
                        "UPDATE signatures.name failed at 0x" + std::to_string(row.owner_addr));
                    return false;
                }
                row.name = next;
                return true;
            })
        .column_text_rw(
            "prototype",
            [](const model::SignatureRow& r) { return r.prototype; },
            [source](model::SignatureRow& row, const char* prototype) {
                const std::string next = prototype ? prototype : "";
                if (row.prototype == next) {
                    return true;
                }
                if (!source->set_function_signature(row.owner_addr, next)) {
                    report_write_error(
                        source,
                        "UPDATE signatures.prototype failed at 0x" + std::to_string(row.owner_addr));
                    return false;
                }
                row.prototype = next;
                row.is_variadic = next.find("...") != std::string::npos ? 1 : 0;
                return true;
            })
        .column_text("calling_convention", [](const model::SignatureRow& r) { return r.calling_convention; })
        .column_int("is_variadic", [](const model::SignatureRow& r) { return r.is_variadic; })
        .column_text("return_type", [](const model::SignatureRow& r) { return r.return_type; })
        .column_int64("param_count", [](const model::SignatureRow& r) { return r.param_count; })
        .build();
}

inline xsql::CachedTableDef<model::FunctionParamRow> define_function_params(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::FunctionParamRow>("function_params")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionParamRow> rows;
            if (source->read_function_params(rows)) {
                return rows.size();
            }
            std::vector<model::FunctionRow> funcs;
            if (source->read_functions(funcs)) {
                return std::max<size_t>(funcs.size(), 1);
            }
            return size_t(0);
        })
        .cache_builder([source](std::vector<model::FunctionParamRow>& out) {
            if (!source->read_function_params(out)) {
                out = derive_function_param_rows(source);
            }
        })
        .column_int64("func_addr", [](const model::FunctionParamRow& r) { return r.func_addr; })
        .column_int64("ordinal", [](const model::FunctionParamRow& r) { return r.ordinal; })
        .column_text_rw(
            "param_name",
            [](const model::FunctionParamRow& r) { return r.param_name; },
            [source](model::FunctionParamRow& row, const char* text) {
                const std::string next = text ? text : "";
                if (row.param_name == next) {
                    return true;
                }
                if (!source->rename_function_param(row.func_addr, row.ordinal, next)) {
                    xsql::set_vtab_error("UPDATE function_params.param_name failed: rename_function_param at 0x" +
                        std::to_string(row.func_addr));
                    return false;
                }
                row.param_name = next;
                return true;
            })
        .column_text_rw(
            "param_type",
            [](const model::FunctionParamRow& r) { return r.param_type; },
            [source](model::FunctionParamRow& row, const char* text) {
                const std::string next = text ? text : "";
                if (row.param_type == next) {
                    return true;
                }
                if (!source->set_function_param_type(row.func_addr, row.ordinal, next)) {
                    xsql::set_vtab_error("UPDATE function_params.param_type failed: set_function_param_type at 0x" +
                        std::to_string(row.func_addr));
                    return false;
                }
                row.param_type = next;
                return true;
            })
        .column_text("storage", [](const model::FunctionParamRow& r) { return r.storage; })
        .column_int("is_user_named", [](const model::FunctionParamRow& r) { return r.is_user_named; })
        .build();
}

inline xsql::CachedTableDef<model::FunctionFrameRow> define_function_frames(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::FunctionFrameRow>("function_frames")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> fns;
            return source->read_functions(fns) ? fns.size() : size_t(100);
        })
        .cache_builder([source](std::vector<model::FunctionFrameRow>& out) {
            out = derive_function_frame_rows(source);
        })
        .column_int64("func_addr", [](const model::FunctionFrameRow& r) { return r.func_addr; })
        .column_int64("frame_size", [](const model::FunctionFrameRow& r) { return r.frame_size; })
        .column_int64("arg_size", [](const model::FunctionFrameRow& r) { return r.arg_size; })
        .column_int64("local_size", [](const model::FunctionFrameRow& r) { return r.local_size; })
        .column_int64("saved_reg_size", [](const model::FunctionFrameRow& r) { return r.saved_reg_size; })
        .column_text("stack_base_reg", [](const model::FunctionFrameRow& r) { return r.stack_base_reg; })
        .column_int("has_frame_pointer", [](const model::FunctionFrameRow& r) { return r.has_frame_pointer; })
        .index_on("func_addr", [](const model::FunctionFrameRow& r) { return r.func_addr; })
        .build();
}

inline xsql::CachedTableDef<model::TextIndexRow> define_text_index(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::TextIndexRow>("text_index")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(5000); })
        .cache_builder([source](std::vector<model::TextIndexRow>& out) {
            out = derive_text_index_rows(source);
        })
        .column_text("doc_id", [](const model::TextIndexRow& r) { return r.doc_id; })
        .column_text("domain", [](const model::TextIndexRow& r) { return r.domain; })
        .column_int64("address", [](const model::TextIndexRow& r) { return r.address; })
        .column_int64("func_addr", [](const model::TextIndexRow& r) { return r.func_addr; })
        .column_text("text", [](const model::TextIndexRow& r) { return r.text; })
        .column_text("norm_text", [](const model::TextIndexRow& r) { return r.norm_text; })
        .index_on("address", [](const model::TextIndexRow& r) { return r.address; })
        .index_on("func_addr", [](const model::TextIndexRow& r) { return r.func_addr; })
        .build();
}

inline xsql::CachedTableDef<model::SearchIndexRow> define_search_index(
    const std::shared_ptr<Source>& source,
    const std::shared_ptr<QueryScopeState>& query_scope) {
    return xsql::cached_table<model::SearchIndexRow>("search_index")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(10000); })
        .cache_builder([source, query_scope](std::vector<model::SearchIndexRow>& out) {
            out = derive_search_index_rows(source);
            query_scope->search_index_rows.store(out);
        })
        .column_text("term", [](const model::SearchIndexRow& r) { return r.term; })
        .column_text("domain", [](const model::SearchIndexRow& r) { return r.domain; })
        .column_text("doc_id", [](const model::SearchIndexRow& r) { return r.doc_id; })
        .column_int64("address", [](const model::SearchIndexRow& r) { return r.address; })
        .column_int64("func_addr", [](const model::SearchIndexRow& r) { return r.func_addr; })
        .column_int64("hit_count", [](const model::SearchIndexRow& r) { return r.hit_count; })
        .column_double("rank", [](const model::SearchIndexRow& r) { return r.rank; })
        .filter_eq_text(
            "term",
            [query_scope, source](const char* term) -> std::unique_ptr<xsql::RowIterator> {
                auto rows = query_scope->search_index_rows.snapshot();
                if (rows.empty()) {
                    rows = derive_search_index_rows(source);
                    query_scope->search_index_rows.store(rows);
                }
                const std::string needle = term ? term : "";
                std::vector<model::SearchIndexRow> filtered;
                filtered.reserve(rows.size());
                for (const auto& row : rows) {
                    if (row.term == needle) {
                        filtered.push_back(row);
                    }
                }
                return std::make_unique<OwnedRowIterator<model::SearchIndexRow>>(
                    std::move(filtered),
                    [](xsql::FunctionContext& ctx, int col, const model::SearchIndexRow& row) {
                        switch (col) {
                        case 0: ctx.result_text(row.term); return;
                        case 1: ctx.result_text(row.domain); return;
                        case 2: ctx.result_text(row.doc_id); return;
                        case 3: ctx.result_int64(row.address); return;
                        case 4: ctx.result_int64(row.func_addr); return;
                        case 5: ctx.result_int64(row.hit_count); return;
                        case 6: ctx.result_double(row.rank); return;
                        default: ctx.result_null(); return;
                        }
                    });
            },
            6.0,
            16.0)
        .index_on("address", [](const model::SearchIndexRow& r) { return r.address; })
        .index_on("func_addr", [](const model::SearchIndexRow& r) { return r.func_addr; })
        .build();
}

inline xsql::CachedTableDef<model::XrefIndexRow> define_xref_index(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::XrefIndexRow>("xref_index")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::XrefRow> rows;
            return source->read_xrefs(rows) ? rows.size() : size_t(1000);
        })
        .cache_builder([source](std::vector<model::XrefIndexRow>& out) {
            out = derive_xref_index_rows(source);
        })
        .column_int64("from_ea", [](const model::XrefIndexRow& r) { return r.from_ea; })
        .column_int64("to_ea", [](const model::XrefIndexRow& r) { return r.to_ea; })
        .column_int64("src_func_addr", [](const model::XrefIndexRow& r) { return r.src_func_addr; })
        .column_int64("dst_func_addr", [](const model::XrefIndexRow& r) { return r.dst_func_addr; })
        .column_text("kind", [](const model::XrefIndexRow& r) { return r.kind; })
        .column_int("is_code", [](const model::XrefIndexRow& r) { return r.is_code; })
        .column_int("is_data", [](const model::XrefIndexRow& r) { return r.is_data; })
        .index_on("from_ea", [](const model::XrefIndexRow& r) { return r.from_ea; })
        .index_on("to_ea", [](const model::XrefIndexRow& r) { return r.to_ea; })
        .index_on("src_func_addr", [](const model::XrefIndexRow& r) { return r.src_func_addr; })
        .index_on("dst_func_addr", [](const model::XrefIndexRow& r) { return r.dst_func_addr; })
        .build();
}

inline xsql::CachedTableDef<model::FunctionMetricRow> define_function_metrics(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::FunctionMetricRow>("function_metrics")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> fns;
            return source->read_functions(fns) ? fns.size() : size_t(100);
        })
        .cache_builder([source](std::vector<model::FunctionMetricRow>& out) {
            out = derive_function_metric_rows(source);
        })
        .column_int64("func_addr", [](const model::FunctionMetricRow& r) { return r.func_addr; })
        .column_text("func_name", [](const model::FunctionMetricRow& r) { return r.func_name; })
        .column_int64("size", [](const model::FunctionMetricRow& r) { return r.size; })
        .column_int64("instruction_count", [](const model::FunctionMetricRow& r) { return r.instruction_count; })
        .column_int64("block_count", [](const model::FunctionMetricRow& r) { return r.block_count; })
        .column_int64("edge_count", [](const model::FunctionMetricRow& r) { return r.edge_count; })
        .column_int64("cyclomatic_complexity", [](const model::FunctionMetricRow& r) { return r.cyclomatic_complexity; })
        .column_int64("call_in_count", [](const model::FunctionMetricRow& r) { return r.call_in_count; })
        .column_int64("call_out_count", [](const model::FunctionMetricRow& r) { return r.call_out_count; })
        .column_int64("string_ref_count", [](const model::FunctionMetricRow& r) { return r.string_ref_count; })
        .column_int64("token_count", [](const model::FunctionMetricRow& r) { return r.token_count; })
        .index_on("func_addr", [](const model::FunctionMetricRow& r) { return r.func_addr; })
        .build();
}

inline xsql::CachedTableDef<model::PseudocodeRow> define_pseudocode(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::PseudocodeRow>("pseudocode")
        .no_shared_cache()
        .estimate_rows([source]() {
            // Cheap estimate: one pseudocode row per function.
            // Do NOT call read_pseudocode() — it triggers full decompilation.
            std::vector<model::FunctionRow> funcs;
            return source->read_functions(funcs) ? funcs.size() : size_t(100);
        })
        .cache_builder([source](std::vector<model::PseudocodeRow>& out) {
            out = derive_pseudocode_rows(source);
        })
        .column_int64("func_addr", [](const model::PseudocodeRow& r) { return r.func_addr; })
        .column_text("func_name", [](const model::PseudocodeRow& r) { return r.func_name; })
        .column_text("text", [](const model::PseudocodeRow& r) { return r.text; })
        .column_int("is_stale", [](const model::PseudocodeRow& r) { return r.is_stale; })
        .filter_eq("func_addr",
            [source](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                auto rows = derive_pseudocode_row_for(source, func_addr);
                return std::make_unique<OwnedRowIterator<model::PseudocodeRow>>(std::move(rows), column_pseudocode);
            }, 1.0, 1.0)
        .build();
}

inline xsql::CachedTableDef<model::DecompLvarRow> define_decomp_lvars(
    const std::shared_ptr<Source>& source,
    const std::shared_ptr<QueryScopeState>& query_scope) {
    // Rowid encoding: func_addr * kLocalsPerFunction + local_index.
    // This lets filter_eq and row_lookup decompile only the target function
    // instead of ALL functions, which is critical for live sources where each
    // decompilation is an RPC call.
    constexpr std::int64_t kLocalsPerFunction = 0x10000;  // 65536 locals/function max

    return xsql::cached_table<model::DecompLvarRow>("decomp_lvars")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> funcs;
            return source->read_functions(funcs) ? std::max<size_t>(funcs.size() * 2, 1) : size_t(100);
        })
        .cache_builder([source, query_scope](std::vector<model::DecompLvarRow>& out) {
            auto indexed = derive_indexed_decomp_lvar_rows(source);
            out.clear();
            out.reserve(indexed.size());
            for (const auto& entry : indexed) {
                out.push_back(entry.second);
            }
            query_scope->decomp_lvar_rows.store(std::move(indexed));
        })
        .column_int64("func_addr", [](const model::DecompLvarRow& r) { return r.func_addr; })
        .column_text("local_id", [](const model::DecompLvarRow& r) { return r.local_id; })
        .column_text_rw(
            "name",
            [](const model::DecompLvarRow& r) { return r.name; },
            [source](model::DecompLvarRow& row, const char* value) {
                const std::string next = value ? value : "";
                if (next == row.name) return true;
                if (!source->rename_decomp_local(row.func_addr, row.local_id, next)) {
                    report_write_error(source,
                        "UPDATE decomp_lvars.name failed for local_id '" + row.local_id +
                        "' at 0x" + std::to_string(row.func_addr));
                    return false;
                }
                row.name = next;
                return true;
            })
        .column_text_rw(
            "type",
            [](const model::DecompLvarRow& r) { return r.type; },
            [source](model::DecompLvarRow& row, const char* value) {
                const std::string next = value ? value : "";
                if (next == row.type) return true;
                if (!source->set_decomp_local_type(row.func_addr, row.local_id, next)) {
                    report_write_error(source,
                        "UPDATE decomp_lvars.type failed for local_id '" + row.local_id +
                        "' at 0x" + std::to_string(row.func_addr));
                    return false;
                }
                row.type = next;
                return true;
            })
        .column_text("storage", [](const model::DecompLvarRow& r) { return r.storage; })
        .column_text("role", [](const model::DecompLvarRow& r) { return r.role; })
        .row_populator([](model::DecompLvarRow& row, int argc, xsql::FunctionArg* argv) {
            // argv[0]=old_rowid, argv[1]=new_rowid, argv[2..]=columns
            if (argc > 2) row.func_addr = argv[2].as_int64();
            if (argc > 3) row.local_id = argv[3].as_text();
            if (argc > 6) row.storage = argv[6].as_text();
            if (argc > 7) row.role = argv[7].as_text();
        })
        .row_lookup([source, query_scope, kLocalsPerFunction](model::DecompLvarRow& row, std::int64_t raw_rowid) {
            if (raw_rowid < 0) {
                return false;
            }
            if (query_scope->decomp_lvar_rows.lookup(raw_rowid, row)) {
                return true;
            }
            const std::int64_t func_addr = raw_rowid / kLocalsPerFunction;
            const auto local_index = static_cast<size_t>(raw_rowid % kLocalsPerFunction);
            auto rows = derive_decomp_lvar_rows_for(source, func_addr);
            if (local_index < rows.size()) {
                row = std::move(rows[local_index]);
                return true;
            }
            return false;
        })
        .filter_eq("func_addr",
            [source, query_scope, kLocalsPerFunction](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                // Only decompile the target function — O(1) RPCs, not O(N_functions).
                auto rows = derive_decomp_lvar_rows_for(source, func_addr);
                std::vector<std::pair<std::int64_t, model::DecompLvarRow>> indexed;
                indexed.reserve(rows.size());
                for (std::int64_t i = 0; i < static_cast<std::int64_t>(rows.size()); ++i) {
                    indexed.emplace_back(func_addr * kLocalsPerFunction + i, std::move(rows[i]));
                }
                query_scope->decomp_lvar_rows.store(indexed);
                return std::make_unique<IndexedOwnedRowIterator<model::DecompLvarRow>>(
                    std::move(indexed),
                    column_decomp_lvar);
            }, 1.0, 4.0)
        .build();
}

inline xsql::CachedTableDef<model::DecompCommentRow> define_decomp_comments(const std::shared_ptr<Source>& source) {
    constexpr std::int64_t kLocalsPerFunction = 0x10000;

    return xsql::cached_table<model::DecompCommentRow>("decomp_comments")
        .no_shared_cache()
        .estimate_rows([source]() {
            // Cheap estimate based on function count.
            // Do NOT call read_decomp_comments() — it may trigger expensive bulk reads.
            std::vector<model::FunctionRow> funcs;
            return source->read_functions(funcs) ? funcs.size() : size_t(100);
        })
        .cache_builder([source](std::vector<model::DecompCommentRow>& out) {
            out = derive_decomp_comment_rows(source);
        })
        .column_int64("func_addr", [](const model::DecompCommentRow& r) { return r.func_addr; })
        .column_int64("address", [](const model::DecompCommentRow& r) { return r.address; })
        .column_text_rw(
            "comment",
            [](const model::DecompCommentRow& r) { return r.comment; },
            [source](model::DecompCommentRow& row, const char* text) {
                const std::string next = text ? text : "";
                const bool prefer_repeatable = decomp_comment_source_is_repeatable(row.source);
                if (!source->set_comment(row.address, next, prefer_repeatable) &&
                    !source->set_comment(row.address, next, !prefer_repeatable)) {
                    report_write_error(
                        source,
                        "UPDATE decomp_comments.comment failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.comment = next;
                return true;
            })
        .column_text_rw(
            "source",
            [](const model::DecompCommentRow& r) { return r.source; },
            [source](model::DecompCommentRow& row, const char* text) {
                // row_populator may fill row.source from a nochange sentinel
                // (appears as NULL/""), so use it only when non-empty.
                const std::string next = text ? text : "eol";
                if (row.source == next || (!text && row.source.empty())) {
                    return true;
                }
                if (!source->set_comment_by_kind(row.address, row.comment, next)) {
                    report_write_error(
                        source,
                        "UPDATE decomp_comments.source failed at 0x" + std::to_string(row.address));
                    return false;
                }
                if (!row.source.empty()) {
                    source->delete_comment_by_kind(row.address, row.source);
                }
                row.source = next;
                return true;
            })
        .deletable([source](model::DecompCommentRow& row) {
            if (source->delete_comment_by_kind(row.address, row.source)) {
                return true;
            }
            const bool prefer_repeatable = decomp_comment_source_is_repeatable(row.source);
            if (source->delete_comment(row.address, prefer_repeatable)) {
                return true;
            }
            return source->delete_comment(row.address, !prefer_repeatable);
        })
        .row_lookup([source, kLocalsPerFunction](model::DecompCommentRow& row, std::int64_t raw_rowid) {
            if (raw_rowid < 0) {
                return false;
            }
            const std::int64_t func_addr = raw_rowid / kLocalsPerFunction;
            const auto slot = static_cast<size_t>(raw_rowid % kLocalsPerFunction);
            auto rows = derive_decomp_comment_rows_for(source, func_addr);
            if (slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .filter_eq("func_addr",
            [source, kLocalsPerFunction](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                auto rows = derive_decomp_comment_rows_for(source, func_addr);
                std::vector<std::pair<std::int64_t, model::DecompCommentRow>> indexed;
                indexed.reserve(rows.size());
                for (std::int64_t i = 0; i < static_cast<std::int64_t>(rows.size()); ++i) {
                    indexed.emplace_back(func_addr * kLocalsPerFunction + i, std::move(rows[static_cast<size_t>(i)]));
                }
                return std::make_unique<IndexedOwnedRowIterator<model::DecompCommentRow>>(
                    std::move(indexed),
                    column_decomp_comment);
            }, 1.0, 4.0)
        .row_populator([](model::DecompCommentRow& row, int argc, xsql::FunctionArg* argv) {
            // Only populate key/read-only columns. Writable columns (comment,
            // source) are left empty so column setters can detect actual changes
            // — argv carries the NEW value for SET columns, which would cause
            // the setter's no-op early return to fire incorrectly.
            if (argc > 2) row.func_addr = argv[2].as_int64();
            if (argc > 3) row.address = argv[3].as_int64();
            // argv[4] = comment (writable) — skip
            if (argc > 5) row.source = argv[5].as_c_str() ? argv[5].as_c_str() : "";
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            const auto address = arg_int64_opt(argc, argv, 1);
            if (!address) {
                xsql::set_vtab_error("INSERT INTO decomp_comments requires address");
                return false;
            }

            const auto comment = arg_text_opt(argc, argv, 2);
            const auto source_kind = arg_text_opt(argc, argv, 3);
            bool repeatable = false;
            if (source_kind && !source_kind->empty()) {
                const auto source_lower = lower_copy(*source_kind);
                repeatable = source_lower.find("repeatable") != std::string::npos;
            }
            return comment_insert_common(source, "decomp_comments", *address, comment, source_kind, repeatable);
        })
        .build();
}

inline xsql::CachedTableDef<model::DecompTokenRow> define_decomp_tokens(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::DecompTokenRow>("decomp_tokens")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> funcs;
            return source->read_functions(funcs) ? std::max<size_t>(funcs.size() * 8, 8) : size_t(100);
        })
        .cache_builder([source](std::vector<model::DecompTokenRow>& out) {
            out = derive_decomp_token_rows(source);
        })
        .column_int64("func_addr", [](const model::DecompTokenRow& r) { return r.func_addr; })
        .column_int64("token_index", [](const model::DecompTokenRow& r) { return r.token_index; })
        .column_text("text", [](const model::DecompTokenRow& r) { return r.text; })
        .column_text("kind", [](const model::DecompTokenRow& r) { return r.kind; })
        .column_int("line", [](const model::DecompTokenRow& r) { return r.line; })
        .column_int("column", [](const model::DecompTokenRow& r) { return r.column; })
        .column_text("var_name", [](const model::DecompTokenRow& r) { return r.var_name; })
        .column_text("var_type", [](const model::DecompTokenRow& r) { return r.var_type; })
        .column_text("var_storage", [](const model::DecompTokenRow& r) { return r.var_storage; })
        .filter_eq("func_addr",
            [source](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                auto rows = derive_decomp_token_rows_for(source, func_addr);
                return std::make_unique<OwnedRowIterator<model::DecompTokenRow>>(std::move(rows), column_decomp_token);
            }, 1.0, 16.0)
        .build();
}

inline xsql::CachedTableDef<model::CapabilityRow> define_sql_capabilities(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::CapabilityRow>("sql_capabilities")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::CapabilityRow> rows;
            if (source->read_capabilities(rows) && !rows.empty()) {
                return rows.size();
            }
            return size_t(0);
        })
        .cache_builder([source](std::vector<model::CapabilityRow>& out) {
            out.clear();
            source->read_capabilities(out);
        })
        .column_text("area", [](const model::CapabilityRow& r) { return r.area; })
        .column_text("feature", [](const model::CapabilityRow& r) { return r.feature; })
        .column_text("state", [](const model::CapabilityRow& r) { return r.state; })
        .column_text("notes", [](const model::CapabilityRow& r) { return r.notes; })
        .column_text("since_rev", [](const model::CapabilityRow& r) { return r.since_rev; })
        .build();
}

inline xsql::CachedTableDef<model::ParityFindingRow> define_parity_findings(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::ParityFindingRow>("parity_findings")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::ParityFindingRow> source_rows;
            source->read_parity_findings(source_rows);
            return source_rows.size();
        })
        .cache_builder([source](std::vector<model::ParityFindingRow>& out) {
            out.clear();
            source->read_parity_findings(out);
        })
        .column_text("finding_id", [](const model::ParityFindingRow& r) { return r.finding_id; })
        .column_text("source_suite", [](const model::ParityFindingRow& r) { return r.source_suite; })
        .column_text("source_test", [](const model::ParityFindingRow& r) { return r.source_test; })
        .column_text("category", [](const model::ParityFindingRow& r) { return r.category; })
        .column_text("severity", [](const model::ParityFindingRow& r) { return r.severity; })
        .column_text("status", [](const model::ParityFindingRow& r) { return r.status; })
        .column_text("owner", [](const model::ParityFindingRow& r) { return r.owner; })
        .column_text("notes", [](const model::ParityFindingRow& r) { return r.notes; })
        .build();
}

inline xsql::CachedTableDef<model::PerfBenchmarkRow> define_perf_benchmarks(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::PerfBenchmarkRow>("perf_benchmarks")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::PerfBenchmarkRow> source_rows;
            source->read_perf_benchmarks(source_rows);
            return source_rows.size();
        })
        .cache_builder([source](std::vector<model::PerfBenchmarkRow>& out) {
            out.clear();
            source->read_perf_benchmarks(out);
        })
        .column_text("bench_id", [](const model::PerfBenchmarkRow& r) { return r.bench_id; })
        .column_text("query_family", [](const model::PerfBenchmarkRow& r) { return r.query_family; })
        .column_text("dataset_profile", [](const model::PerfBenchmarkRow& r) { return r.dataset_profile; })
        .column_double("cold_ms_p50", [](const model::PerfBenchmarkRow& r) { return r.cold_ms_p50; })
        .column_double("cold_ms_p95", [](const model::PerfBenchmarkRow& r) { return r.cold_ms_p95; })
        .column_double("warm_ms_p50", [](const model::PerfBenchmarkRow& r) { return r.warm_ms_p50; })
        .column_double("warm_ms_p95", [](const model::PerfBenchmarkRow& r) { return r.warm_ms_p95; })
        .column_double("throughput_qps", [](const model::PerfBenchmarkRow& r) { return r.throughput_qps; })
        .column_double("regression_pct", [](const model::PerfBenchmarkRow& r) { return r.regression_pct; })
        .column_text("status", [](const model::PerfBenchmarkRow& r) { return r.status; })
        .build();
}

inline xsql::CachedTableDef<model::LiveMetaRow> define_live_meta(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::LiveMetaRow>("live_meta")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::LiveMetaRow> rows;
            source->read_live_meta(rows);
            return rows.size();
        })
        .cache_builder([source](std::vector<model::LiveMetaRow>& out) {
            out.clear();
            source->read_live_meta(out);
        })
        .column_text("live_id", [](const model::LiveMetaRow& r) { return r.live_id; })
        .column_text("source_mode", [](const model::LiveMetaRow& r) { return r.source_mode; })
        .column_text("program_id", [](const model::LiveMetaRow& r) { return r.program_id; })
        .column_int64("revision", [](const model::LiveMetaRow& r) { return r.revision; })
        .column_text("created_at", [](const model::LiveMetaRow& r) { return r.created_at; })
        .column_text("row_counts_json", [](const model::LiveMetaRow& r) { return r.row_counts_json; })
        .column_text("lineage", [](const model::LiveMetaRow& r) { return r.lineage; })
        .build();
}

inline void column_breakpoint(xsql::FunctionContext& ctx, int col, const model::BreakpointRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_int(r.enabled); return;
        case 2: ctx.result_int(r.type); return;
        case 3: ctx.result_text(breakpoint_type_name(r.type)); return;
        case 4: ctx.result_int64(r.size); return;
        case 5: ctx.result_int64(r.flags); return;
        case 6: ctx.result_int(r.pass_count); return;
        case 7: ctx.result_text(r.condition); return;
        case 8: ctx.result_text(r.group); return;
        case 9: ctx.result_int(r.loc_type); return;
        case 10: ctx.result_text(breakpoint_loc_type_name(r.loc_type)); return;
        default: ctx.result_null(); return;
    }
}

inline void column_bookmark(xsql::FunctionContext& ctx, int col, const model::BookmarkRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_text(r.type); return;
        case 2: ctx.result_text(r.category); return;
        case 3: ctx.result_text(r.comment); return;
        default: ctx.result_null(); return;
    }
}

inline xsql::CachedTableDef<model::BreakpointRow> define_breakpoints(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::BreakpointRow>("breakpoints")
        .no_shared_cache()
        .cache_builder([source](std::vector<model::BreakpointRow>& out) {
            if (!source->read_breakpoints(out)) { out.clear(); }
        })
        .column_int64("address", [](const model::BreakpointRow& r) { return r.address; })
        .column_int_rw(
            "enabled",
            [](const model::BreakpointRow& r) { return r.enabled; },
            [source](model::BreakpointRow& row, int value) {
                if (!source->set_breakpoint_enabled(row.address, value != 0)) {
                    report_write_error(source, "UPDATE breakpoints.enabled failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.enabled = value != 0 ? 1 : 0;
                return true;
            })
        .column_int_rw(
            "type",
            [](const model::BreakpointRow& r) { return r.type; },
            [source](model::BreakpointRow& row, int value) {
                if (!source->set_breakpoint_type(row.address, value)) {
                    report_write_error(source, "UPDATE breakpoints.type failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.type = value;
                return true;
            })
        .column_text("type_name", [](const model::BreakpointRow& r) {
            return std::string(breakpoint_type_name(r.type));
        })
        .column_int64_rw(
            "size",
            [](const model::BreakpointRow& r) { return r.size; },
            [source](model::BreakpointRow& row, std::int64_t value) {
                if (!source->set_breakpoint_size(row.address, value)) {
                    report_write_error(source, "UPDATE breakpoints.size failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.size = value;
                return true;
            })
        .column_int64("flags", [](const model::BreakpointRow& r) { return r.flags; })
        .column_int("pass_count", [](const model::BreakpointRow& r) { return r.pass_count; })
        .column_text_rw(
            "condition",
            [](const model::BreakpointRow& r) { return r.condition; },
            [source](model::BreakpointRow& row, const char* value) {
                if (!source->set_breakpoint_condition(row.address, value ? value : "")) {
                    report_write_error(source, "UPDATE breakpoints.condition failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.condition = value ? value : "";
                return true;
            })
        .column_text_rw(
            "group",
            [](const model::BreakpointRow& r) { return r.group; },
            [source](model::BreakpointRow& row, const char* value) {
                if (!source->set_breakpoint_group(row.address, value ? value : "")) {
                    report_write_error(source, "UPDATE breakpoints.group failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.group = value ? value : "";
                return true;
            })
        .column_int("loc_type", [](const model::BreakpointRow& r) { return r.loc_type; })
        .column_text("loc_type_name", [](const model::BreakpointRow& r) {
            return std::string(breakpoint_loc_type_name(r.loc_type));
        })
        .deletable([source](model::BreakpointRow& row) {
            if (!source->delete_breakpoint(row.address)) {
                report_write_error(source, "DELETE FROM breakpoints failed at 0x" + std::to_string(row.address));
                return false;
            }
            return true;
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            if (argc < 1 || argv[0].is_null()) {
                xsql::set_vtab_error("INSERT INTO breakpoints requires address");
                return false;
            }
            const std::int64_t address = argv[0].as_int64();
            const int type = (argc > 2 && !argv[2].is_null()) ? argv[2].as_int() : 0;
            const std::int64_t size = (argc > 4 && !argv[4].is_null()) ? argv[4].as_int64() : 1;
            const std::string condition = (argc > 7 && !argv[7].is_null())
                ? argv[7].as_text()
                : std::string{};
            const std::string group = (argc > 8 && !argv[8].is_null())
                ? argv[8].as_text()
                : std::string{};

            if (!source->add_breakpoint(address, type, size, condition, group)) {
                report_write_error(source, "INSERT INTO breakpoints failed at 0x" + std::to_string(address));
                return false;
            }
            if (argc > 1 && !argv[1].is_null() && argv[1].as_int() == 0) {
                return source->set_breakpoint_enabled(address, false);
            }
            return true;
        })
        .row_lookup([source](model::BreakpointRow& row, std::int64_t raw_rowid) {
            std::int64_t address = 0;
            size_t slot = 0;
            if (!decode_address_rowid(raw_rowid, address, slot)) {
                return false;
            }
            std::vector<model::BreakpointRow> rows;
            if (!source->read_breakpoints_at(address, rows) || slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .filter_eq("address",
            [source](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::BreakpointRow> rows;
                source->read_breakpoints_at(address, rows);
                std::vector<std::pair<std::int64_t, model::BreakpointRow>> indexed;
                indexed.reserve(rows.size());
                for (size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(encode_address_rowid(address, i), std::move(rows[i]));
                }
                return std::make_unique<IndexedOwnedRowIterator<model::BreakpointRow>>(
                    std::move(indexed),
                    column_breakpoint);
            }, 1.0, 2.0)
        .build();
}

inline xsql::CachedTableDef<model::BookmarkRow> define_bookmarks(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::BookmarkRow>("bookmarks")
        .no_shared_cache()
        .cache_builder([source](std::vector<model::BookmarkRow>& out) {
            if (!source->read_bookmarks(out)) { out.clear(); }
        })
        .column_int64("address", [](const model::BookmarkRow& r) { return r.address; })
        .column_text_rw(
            "type",
            [](const model::BookmarkRow& r) { return r.type; },
            [source](model::BookmarkRow& row, const char* value) {
                const std::string next = value ? value : "";
                if (next.empty()) {
                    xsql::set_vtab_error("UPDATE bookmarks.type: type must not be empty");
                    return false;
                }
                if (!source->set_bookmark_type(row.address, row.type, row.category, next)) {
                    report_write_error(source, "UPDATE bookmarks.type failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.type = next;
                return true;
            })
        .column_text_rw(
            "category",
            [](const model::BookmarkRow& r) { return r.category; },
            [source](model::BookmarkRow& row, const char* value) {
                const std::string next = value ? value : "";
                if (!source->set_bookmark_category(row.address, row.type, row.category, next)) {
                    report_write_error(source, "UPDATE bookmarks.category failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.category = next;
                return true;
            })
        .column_text_rw(
            "comment",
            [](const model::BookmarkRow& r) { return r.comment; },
            [source](model::BookmarkRow& row, const char* value) {
                if (!source->set_bookmark_comment(row.address, row.type, row.category, value ? value : "")) {
                    report_write_error(source, "UPDATE bookmarks.comment failed at 0x" + std::to_string(row.address));
                    return false;
                }
                row.comment = value ? value : "";
                return true;
            })
        .deletable([source](model::BookmarkRow& row) {
            if (!source->delete_bookmark(row.address, row.type, row.category)) {
                report_write_error(source, "DELETE FROM bookmarks failed at 0x" + std::to_string(row.address));
                return false;
            }
            return true;
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            if (argc < 1 || argv[0].is_null()) {
                xsql::set_vtab_error("INSERT INTO bookmarks requires address");
                return false;
            }
            const std::int64_t address = argv[0].as_int64();
            std::string type = (argc > 1 && !argv[1].is_null())
                ? argv[1].as_text()
                : std::string("Analysis");
            const std::string category = (argc > 2 && !argv[2].is_null())
                ? argv[2].as_text()
                : std::string{};
            const std::string comment = (argc > 3 && !argv[3].is_null())
                ? argv[3].as_text()
                : std::string{};
            if (type.empty()) {
                type = "Analysis";
            }
            if (!source->add_bookmark(address, type, category, comment)) {
                report_write_error(source, "INSERT INTO bookmarks failed at 0x" + std::to_string(address));
                return false;
            }
            return true;
        })
        .row_lookup([source](model::BookmarkRow& row, std::int64_t raw_rowid) {
            std::int64_t address = 0;
            size_t slot = 0;
            if (!decode_address_rowid(raw_rowid, address, slot)) {
                return false;
            }
            std::vector<model::BookmarkRow> rows;
            if (!source->read_bookmarks_at(address, rows) || slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .filter_eq("address",
            [source](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::BookmarkRow> rows;
                source->read_bookmarks_at(address, rows);
                std::vector<std::pair<std::int64_t, model::BookmarkRow>> indexed;
                indexed.reserve(rows.size());
                for (size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(encode_address_rowid(address, i), std::move(rows[i]));
                }
                return std::make_unique<IndexedOwnedRowIterator<model::BookmarkRow>>(
                    std::move(indexed),
                    column_bookmark);
            }, 1.0, 4.0)
        .build();
}

// ── Function tags ─────────────────────────────────────────────────────

inline xsql::CachedTableDef<model::FunctionTagRow> define_function_tags(
    const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::FunctionTagRow>("function_tags")
        .no_shared_cache()
        .cache_builder([source](std::vector<model::FunctionTagRow>& out) {
            return source->read_function_tags(out);
        })
        .column_text("name", [](const model::FunctionTagRow& r) { return r.name; })
        .column_text("comment", [](const model::FunctionTagRow& r) { return r.comment; })
        .deletable([source](const model::FunctionTagRow& row) {
            if (!source->delete_function_tag(row.name)) {
                report_write_error(source, "DELETE FROM function_tags failed for '" + row.name + "'");
                return false;
            }
            return true;
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            if (argc < 1 || argv[0].is_null()) {
                xsql::set_vtab_error("INSERT INTO function_tags requires name");
                return false;
            }
            const std::string name = argv[0].as_text();
            const std::string comment = (argc > 1 && !argv[1].is_null())
                ? argv[1].as_text()
                : std::string{};
            if (!source->create_function_tag(name, comment)) {
                report_write_error(source, "INSERT INTO function_tags failed for '" + name + "'");
                return false;
            }
            return true;
        })
        .build();
}

inline xsql::CachedTableDef<model::FunctionTagMappingRow> define_function_tag_mappings(
    const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::FunctionTagMappingRow>("function_tag_mappings")
        .no_shared_cache()
        .cache_builder([source](std::vector<model::FunctionTagMappingRow>& out) {
            return source->read_function_tag_mappings(out);
        })
        .column_int64("func_addr", [](const model::FunctionTagMappingRow& r) { return r.func_addr; })
        .column_text("tag_name", [](const model::FunctionTagMappingRow& r) { return r.tag_name; })
        .deletable([source](const model::FunctionTagMappingRow& row) {
            if (!source->untag_function(row.func_addr, row.tag_name)) {
                report_write_error(source,
                    "DELETE FROM function_tag_mappings failed for tag '" + row.tag_name +
                    "' at 0x" + std::to_string(row.func_addr));
                return false;
            }
            return true;
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
                xsql::set_vtab_error("INSERT INTO function_tag_mappings requires func_addr and tag_name");
                return false;
            }
            const std::int64_t func_addr = argv[0].as_int64();
            const std::string tag_name = argv[1].as_text();
            if (!source->tag_function(func_addr, tag_name)) {
                report_write_error(source,
                    "INSERT INTO function_tag_mappings failed for tag '" + tag_name +
                    "' at 0x" + std::to_string(func_addr));
                return false;
            }
            return true;
        })
        .build();
}

inline xsql::CachedTableDef<model::ProgramInfoRow> define_db_info(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::ProgramInfoRow>("db_info")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(1); })
        .cache_builder([source](std::vector<model::ProgramInfoRow>& out) {
            out.clear();
            model::ProgramInfoRow info;
            if (!source->read_program_info(info)) {
                return;
            }
            out.push_back(std::move(info));
        })
        .column_text("tool_name", [](const model::ProgramInfoRow& r) { return r.tool_name; })
        .column_text("program_name", [](const model::ProgramInfoRow& r) { return r.program_name; })
        .column_text("program_path", [](const model::ProgramInfoRow& r) { return r.program_path; })
        .column_text("language_id", [](const model::ProgramInfoRow& r) { return r.language_id; })
        .column_text("compiler_spec", [](const model::ProgramInfoRow& r) { return r.compiler_spec; })
        .column_text("analysis_id", [](const model::ProgramInfoRow& r) { return r.analysis_id; })
        .column_text("md5", [](const model::ProgramInfoRow& r) { return r.md5; })
        .column_text("sha256", [](const model::ProgramInfoRow& r) { return r.sha256; })
        .column_int64("image_base", [](const model::ProgramInfoRow& r) { return r.image_base; })
        .column_int("is_headless", [](const model::ProgramInfoRow& r) { return r.is_headless; })
        .column_int64("revision", [](const model::ProgramInfoRow& r) { return r.revision; })
        .build();
}

inline xsql::CachedTableDef<model::ProjectFileRow> define_project_files(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::ProjectFileRow>("project_files")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(32); })
        .cache_builder([source](std::vector<model::ProjectFileRow>& out) {
            if (!source->read_project_files(out)) {
                out.clear();
            }
        })
        .column_text("path", [](const model::ProjectFileRow& r) { return r.path; })
        .column_text("name", [](const model::ProjectFileRow& r) { return r.name; })
        .column_text("folder_path", [](const model::ProjectFileRow& r) { return r.folder_path; })
        .column_text("content_type", [](const model::ProjectFileRow& r) { return r.content_type; })
        .column_text("domain_object_class", [](const model::ProjectFileRow& r) { return r.domain_object_class; })
        .column_int("is_folder", [](const model::ProjectFileRow& r) { return r.is_folder; })
        .column_int("is_program", [](const model::ProjectFileRow& r) { return r.is_program; })
        .build();
}

inline xsql::CachedTableDef<model::ProjectFileRow> define_project_programs(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::ProjectFileRow>("project_programs")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(8); })
        .cache_builder([source](std::vector<model::ProjectFileRow>& out) {
            if (!source->read_project_files(out)) {
                out.clear();
                return;
            }
            out.erase(
                std::remove_if(
                    out.begin(),
                    out.end(),
                    [](const model::ProjectFileRow& row) { return row.is_program == 0; }),
                out.end());
        })
        .column_text("path", [](const model::ProjectFileRow& r) { return r.path; })
        .column_text("name", [](const model::ProjectFileRow& r) { return r.name; })
        .column_text("folder_path", [](const model::ProjectFileRow& r) { return r.folder_path; })
        .column_text("content_type", [](const model::ProjectFileRow& r) { return r.content_type; })
        .column_text("domain_object_class", [](const model::ProjectFileRow& r) { return r.domain_object_class; })
        .column_int("is_folder", [](const model::ProjectFileRow& r) { return r.is_folder; })
        .column_int("is_program", [](const model::ProjectFileRow& r) { return r.is_program; })
        .build();
}

struct TableRegistry::Impl {
    explicit Impl(std::shared_ptr<Source> source_)
        : query_scope(std::make_shared<QueryScopeState>())
        , source(std::move(source_))
        , project_files(define_project_files(source))
        , project_programs(define_project_programs(source))
        , funcs(define_funcs(source))
        , segments(define_segments(source))
        , memory_blocks(define_memory_blocks(source))
        , memory_bytes(define_memory_bytes(source))
        , names(define_names(source))
        , imports(define_imports(source))
        , exports(define_exports(source))
        , strings(define_strings(source))
        , xrefs(define_xrefs(source))
        , call_edges(define_call_edges(source))
        , function_calls(define_function_calls(source))
        , blocks(define_blocks(source))
        , cfg_edges(define_cfg_edges(source))
        , loops(define_loops(source))
        , switch_tables(define_switch_tables(source))
        , dominators(define_dominators(source))
        , post_dominators(define_post_dominators(source))
        , instructions(define_instructions(source))
        , comments(define_comments(source))
        , data_items(define_data_items(source))
        , function_locals(define_function_locals(source, query_scope))
        , stack_vars(define_stack_vars(source))
        , register_vars(define_register_vars(source))
        , function_chunks(define_function_chunks(source))
        , tail_calls(define_tail_calls(source))
        , program_options(define_program_options(source))
        , analysis_passes(define_analysis_passes(source))
        , transactions(define_transactions(source))
        , project_properties(define_project_properties(source))
        , relocations(define_relocations(source))
        , constants(define_constants(source))
        , equates(define_equates(source))
        , types(define_types(source))
        , type_members(define_type_members(source))
        , type_enums(define_type_enums(source))
        , type_enum_members(define_type_enum_members(source))
        , type_unions(define_type_unions(source))
        , type_aliases(define_type_aliases(source))
        , signatures(define_signatures(source))
        , function_params(define_function_params(source))
        , function_frames(define_function_frames(source))
        , text_index(define_text_index(source))
        , search_index(define_search_index(source, query_scope))
        , xref_index(define_xref_index(source))
        , function_metrics(define_function_metrics(source))
        , pseudocode(define_pseudocode(source))
        , decomp_lvars(define_decomp_lvars(source, query_scope))
        , decomp_comments(define_decomp_comments(source))
        , decomp_tokens(define_decomp_tokens(source))
        , breakpoints(define_breakpoints(source))
        , bookmarks(define_bookmarks(source))
        , function_tags(define_function_tags(source))
        , function_tag_mappings(define_function_tag_mappings(source))
        , sql_capabilities(define_sql_capabilities(source))
        , parity_findings(define_parity_findings(source))
        , perf_benchmarks(define_perf_benchmarks(source))
        , live_meta(define_live_meta(source))
        , db_info(define_db_info(source)) {}

    void register_all(xsql::Database& db) {
        register_cached(db, "project_files", &project_files);
        register_cached(db, "project_programs", &project_programs);
        register_cached(db, "funcs", &funcs);
        register_cached(db, "segments", &segments);
        register_cached(db, "memory_blocks", &memory_blocks);
        register_cached(db, "memory_bytes", &memory_bytes);
        register_cached(db, "names", &names);
        register_cached(db, "imports", &imports);
        register_cached(db, "exports", &exports);
        register_cached(db, "strings", &strings);
        register_cached(db, "xrefs", &xrefs);
        register_cached(db, "call_edges", &call_edges);
        register_cached(db, "function_calls", &function_calls);
        register_cached(db, "blocks", &blocks);
        register_cached(db, "cfg_edges", &cfg_edges);
        register_cached(db, "loops", &loops);
        register_cached(db, "switch_tables", &switch_tables);
        register_cached(db, "dominators", &dominators);
        register_cached(db, "post_dominators", &post_dominators);
        register_cached(db, "instructions", &instructions);
        register_cached(db, "comments", &comments);
        register_cached(db, "data_items", &data_items);
        register_cached(db, "function_locals", &function_locals);
        register_cached(db, "stack_vars", &stack_vars);
        register_cached(db, "register_vars", &register_vars);
        register_cached(db, "function_chunks", &function_chunks);
        register_cached(db, "tail_calls", &tail_calls);
        register_cached(db, "program_options", &program_options);
        register_cached(db, "analysis_passes", &analysis_passes);
        register_cached(db, "transactions", &transactions);
        register_cached(db, "project_properties", &project_properties);
        register_cached(db, "relocations", &relocations);
        register_cached(db, "constants", &constants);
        register_cached(db, "equates", &equates);
        register_cached(db, "types", &types);
        register_cached(db, "type_members", &type_members);
        register_cached(db, "type_enums", &type_enums);
        register_cached(db, "type_enum_members", &type_enum_members);
        register_cached(db, "type_unions", &type_unions);
        register_cached(db, "type_aliases", &type_aliases);
        register_cached(db, "signatures", &signatures);
        register_cached(db, "function_params", &function_params);
        register_cached(db, "function_frames", &function_frames);
        register_cached(db, "text_index", &text_index);
        register_cached(db, "search_index", &search_index);
        register_cached(db, "xref_index", &xref_index);
        register_cached(db, "function_metrics", &function_metrics);
        register_cached(db, "pseudocode", &pseudocode);
        register_cached(db, "decomp_lvars", &decomp_lvars);
        register_cached(db, "decomp_comments", &decomp_comments);
        register_cached(db, "decomp_tokens", &decomp_tokens);
        register_cached(db, "breakpoints", &breakpoints);
        register_cached(db, "bookmarks", &bookmarks);
        register_cached(db, "function_tags", &function_tags);
        register_cached(db, "function_tag_mappings", &function_tag_mappings);
        register_cached(db, "sql_capabilities", &sql_capabilities);
        register_cached(db, "parity_findings", &parity_findings);
        register_cached(db, "perf_benchmarks", &perf_benchmarks);
        register_cached(db, "live_meta", &live_meta);
        register_cached(db, "db_info", &db_info);
        create_entity_views(db);
    }

    void invalidate_all() const {
        query_scope->reset_all();
        project_files.invalidate_cache();
        project_programs.invalidate_cache();
        funcs.invalidate_cache();
        segments.invalidate_cache();
        memory_blocks.invalidate_cache();
        memory_bytes.invalidate_cache();
        names.invalidate_cache();
        imports.invalidate_cache();
        exports.invalidate_cache();
        strings.invalidate_cache();
        xrefs.invalidate_cache();
        call_edges.invalidate_cache();
        function_calls.invalidate_cache();
        blocks.invalidate_cache();
        cfg_edges.invalidate_cache();
        loops.invalidate_cache();
        switch_tables.invalidate_cache();
        dominators.invalidate_cache();
        post_dominators.invalidate_cache();
        instructions.invalidate_cache();
        comments.invalidate_cache();
        data_items.invalidate_cache();
        function_locals.invalidate_cache();
        stack_vars.invalidate_cache();
        register_vars.invalidate_cache();
        function_chunks.invalidate_cache();
        tail_calls.invalidate_cache();
        program_options.invalidate_cache();
        analysis_passes.invalidate_cache();
        transactions.invalidate_cache();
        project_properties.invalidate_cache();
        relocations.invalidate_cache();
        constants.invalidate_cache();
        equates.invalidate_cache();
        types.invalidate_cache();
        type_members.invalidate_cache();
        type_enums.invalidate_cache();
        type_enum_members.invalidate_cache();
        type_unions.invalidate_cache();
        type_aliases.invalidate_cache();
        signatures.invalidate_cache();
        function_params.invalidate_cache();
        function_frames.invalidate_cache();
        text_index.invalidate_cache();
        search_index.invalidate_cache();
        xref_index.invalidate_cache();
        function_metrics.invalidate_cache();
        pseudocode.invalidate_cache();
        decomp_lvars.invalidate_cache();
        decomp_comments.invalidate_cache();
        decomp_tokens.invalidate_cache();
        breakpoints.invalidate_cache();
        bookmarks.invalidate_cache();
        function_tags.invalidate_cache();
        function_tag_mappings.invalidate_cache();
        sql_capabilities.invalidate_cache();
        parity_findings.invalidate_cache();
        perf_benchmarks.invalidate_cache();
        live_meta.invalidate_cache();
        db_info.invalidate_cache();
    }

    bool invalidate_table(const std::string& name) const {
        query_scope->reset_for_table(name);
        if (name == "funcs") {
            funcs.invalidate_cache();
            return true;
        }
        if (name == "project_files") {
            project_files.invalidate_cache();
            return true;
        }
        if (name == "project_programs") {
            project_programs.invalidate_cache();
            return true;
        }
        if (name == "segments") {
            segments.invalidate_cache();
            return true;
        }
        if (name == "memory_blocks") {
            memory_blocks.invalidate_cache();
            return true;
        }
        if (name == "memory_bytes") {
            memory_bytes.invalidate_cache();
            return true;
        }
        if (name == "names") {
            names.invalidate_cache();
            return true;
        }
        if (name == "imports") {
            imports.invalidate_cache();
            return true;
        }
        if (name == "exports") {
            exports.invalidate_cache();
            return true;
        }
        if (name == "strings") {
            strings.invalidate_cache();
            return true;
        }
        if (name == "xrefs") {
            xrefs.invalidate_cache();
            return true;
        }
        if (name == "call_edges") {
            call_edges.invalidate_cache();
            return true;
        }
        if (name == "function_calls") {
            function_calls.invalidate_cache();
            return true;
        }
        if (name == "blocks") {
            blocks.invalidate_cache();
            return true;
        }
        if (name == "cfg_edges") {
            cfg_edges.invalidate_cache();
            return true;
        }
        if (name == "loops") {
            loops.invalidate_cache();
            return true;
        }
        if (name == "switch_tables") {
            switch_tables.invalidate_cache();
            return true;
        }
        if (name == "dominators") {
            dominators.invalidate_cache();
            return true;
        }
        if (name == "post_dominators") {
            post_dominators.invalidate_cache();
            return true;
        }
        if (name == "instructions") {
            instructions.invalidate_cache();
            return true;
        }
        if (name == "comments") {
            comments.invalidate_cache();
            return true;
        }
        if (name == "data_items") {
            data_items.invalidate_cache();
            return true;
        }
        if (name == "function_locals") {
            function_locals.invalidate_cache();
            return true;
        }
        if (name == "stack_vars") {
            stack_vars.invalidate_cache();
            return true;
        }
        if (name == "register_vars") {
            register_vars.invalidate_cache();
            return true;
        }
        if (name == "function_chunks") {
            function_chunks.invalidate_cache();
            return true;
        }
        if (name == "tail_calls") {
            tail_calls.invalidate_cache();
            return true;
        }
        if (name == "program_options") {
            program_options.invalidate_cache();
            return true;
        }
        if (name == "analysis_passes") {
            analysis_passes.invalidate_cache();
            return true;
        }
        if (name == "transactions") {
            transactions.invalidate_cache();
            return true;
        }
        if (name == "project_properties") {
            project_properties.invalidate_cache();
            return true;
        }
        if (name == "relocations") {
            relocations.invalidate_cache();
            return true;
        }
        if (name == "constants") {
            constants.invalidate_cache();
            return true;
        }
        if (name == "equates") {
            equates.invalidate_cache();
            return true;
        }
        if (name == "types") {
            types.invalidate_cache();
            return true;
        }
        if (name == "type_members") {
            type_members.invalidate_cache();
            return true;
        }
        if (name == "type_enums") {
            type_enums.invalidate_cache();
            return true;
        }
        if (name == "type_enum_members") {
            type_enum_members.invalidate_cache();
            return true;
        }
        if (name == "type_unions") {
            type_unions.invalidate_cache();
            return true;
        }
        if (name == "type_aliases") {
            type_aliases.invalidate_cache();
            return true;
        }
        if (name == "signatures") {
            signatures.invalidate_cache();
            return true;
        }
        if (name == "function_params") {
            function_params.invalidate_cache();
            return true;
        }
        if (name == "function_frames") {
            function_frames.invalidate_cache();
            return true;
        }
        if (name == "text_index") {
            text_index.invalidate_cache();
            return true;
        }
        if (name == "search_index") {
            search_index.invalidate_cache();
            return true;
        }
        if (name == "xref_index") {
            xref_index.invalidate_cache();
            return true;
        }
        if (name == "function_metrics") {
            function_metrics.invalidate_cache();
            return true;
        }
        if (name == "pseudocode") {
            pseudocode.invalidate_cache();
            return true;
        }
        if (name == "decomp_lvars") {
            decomp_lvars.invalidate_cache();
            return true;
        }
        if (name == "decomp_comments") {
            decomp_comments.invalidate_cache();
            return true;
        }
        if (name == "decomp_tokens") {
            decomp_tokens.invalidate_cache();
            return true;
        }
        if (name == "breakpoints") {
            breakpoints.invalidate_cache();
            return true;
        }
        if (name == "bookmarks") {
            bookmarks.invalidate_cache();
            return true;
        }
        if (name == "function_tags") {
            function_tags.invalidate_cache();
            return true;
        }
        if (name == "function_tag_mappings") {
            function_tag_mappings.invalidate_cache();
            return true;
        }
        if (name == "sql_capabilities") {
            sql_capabilities.invalidate_cache();
            return true;
        }
        if (name == "parity_findings") {
            parity_findings.invalidate_cache();
            return true;
        }
        if (name == "perf_benchmarks") {
            perf_benchmarks.invalidate_cache();
            return true;
        }
        if (name == "live_meta") {
            live_meta.invalidate_cache();
            return true;
        }
        if (name == "db_info") {
            db_info.invalidate_cache();
            return true;
        }
        return false;
    }


private:
    template <typename RowData>
    static void register_cached(
        xsql::Database& db,
        const char* table_name,
        const xsql::CachedTableDef<RowData>* def)
    {
        const std::string module_name = std::string("ghidra_") + table_name;
        db.register_cached_table(module_name.c_str(), def);
        db.create_table(table_name, module_name.c_str());
    }

    static void register_index(
        xsql::Database& db,
        const char* table_name,
        const xsql::VTableDef* def)
    {
        const std::string module_name = std::string("ghidra_") + table_name;
        db.register_table(module_name.c_str(), def);
        db.create_table(table_name, module_name.c_str());
    }

public:
    std::shared_ptr<QueryScopeState> query_scope;
    std::shared_ptr<Source> source;
    xsql::CachedTableDef<model::ProjectFileRow> project_files;
    xsql::CachedTableDef<model::ProjectFileRow> project_programs;
    xsql::CachedTableDef<model::FunctionRow> funcs;
    xsql::CachedTableDef<model::SegmentRow> segments;
    xsql::CachedTableDef<model::MemoryBlockRow> memory_blocks;
    xsql::CachedTableDef<model::MemoryByteRow> memory_bytes;
    xsql::CachedTableDef<model::SymbolRow> names;
    xsql::CachedTableDef<model::ImportRow> imports;
    xsql::CachedTableDef<model::ExportRow> exports;
    xsql::CachedTableDef<model::StringRow> strings;
    xsql::CachedTableDef<model::XrefRow> xrefs;
    xsql::CachedTableDef<model::CallEdgeRow> call_edges;
    xsql::CachedTableDef<model::FunctionCallRow> function_calls;
    xsql::CachedTableDef<model::BlockRow> blocks;
    xsql::CachedTableDef<model::CfgEdgeRow> cfg_edges;
    xsql::CachedTableDef<model::LoopRow> loops;
    xsql::CachedTableDef<model::SwitchTableRow> switch_tables;
    xsql::CachedTableDef<model::DominatorRow> dominators;
    xsql::CachedTableDef<model::PostDominatorRow> post_dominators;
    xsql::CachedTableDef<model::InstructionRow> instructions;
    xsql::CachedTableDef<model::CommentRow> comments;
    xsql::CachedTableDef<model::DataItemRow> data_items;
    xsql::CachedTableDef<model::FunctionLocalRow> function_locals;
    xsql::CachedTableDef<model::StackVarRow> stack_vars;
    xsql::CachedTableDef<model::RegisterVarRow> register_vars;
    xsql::CachedTableDef<model::FunctionChunkRow> function_chunks;
    xsql::CachedTableDef<model::TailCallRow> tail_calls;
    xsql::CachedTableDef<model::ProgramOptionRow> program_options;
    xsql::CachedTableDef<model::AnalysisPassRow> analysis_passes;
    xsql::CachedTableDef<model::TransactionRow> transactions;
    xsql::CachedTableDef<model::ProjectPropertyRow> project_properties;
    xsql::CachedTableDef<model::RelocationRow> relocations;
    xsql::CachedTableDef<model::ConstantRow> constants;
    xsql::CachedTableDef<model::EquateRow> equates;
    xsql::CachedTableDef<model::TypeRow> types;
    xsql::CachedTableDef<model::TypeMemberRow> type_members;
    xsql::CachedTableDef<model::TypeEnumRow> type_enums;
    xsql::CachedTableDef<model::TypeEnumMemberRow> type_enum_members;
    xsql::CachedTableDef<model::TypeUnionRow> type_unions;
    xsql::CachedTableDef<model::TypeAliasRow> type_aliases;
    xsql::CachedTableDef<model::SignatureRow> signatures;
    xsql::CachedTableDef<model::FunctionParamRow> function_params;
    xsql::CachedTableDef<model::FunctionFrameRow> function_frames;
    xsql::CachedTableDef<model::TextIndexRow> text_index;
    xsql::CachedTableDef<model::SearchIndexRow> search_index;
    xsql::CachedTableDef<model::XrefIndexRow> xref_index;
    xsql::CachedTableDef<model::FunctionMetricRow> function_metrics;
    xsql::CachedTableDef<model::PseudocodeRow> pseudocode;
    xsql::CachedTableDef<model::DecompLvarRow> decomp_lvars;
    xsql::CachedTableDef<model::DecompCommentRow> decomp_comments;
    xsql::CachedTableDef<model::DecompTokenRow> decomp_tokens;
    xsql::CachedTableDef<model::BreakpointRow> breakpoints;
    xsql::CachedTableDef<model::BookmarkRow> bookmarks;
    xsql::CachedTableDef<model::FunctionTagRow> function_tags;
    xsql::CachedTableDef<model::FunctionTagMappingRow> function_tag_mappings;
    xsql::CachedTableDef<model::CapabilityRow> sql_capabilities;
    xsql::CachedTableDef<model::ParityFindingRow> parity_findings;
    xsql::CachedTableDef<model::PerfBenchmarkRow> perf_benchmarks;
    xsql::CachedTableDef<model::LiveMetaRow> live_meta;
    xsql::CachedTableDef<model::ProgramInfoRow> db_info;
};


TableRegistry::TableRegistry(std::shared_ptr<Source> source)
    : impl_(std::make_unique<Impl>(std::move(source))) {}

TableRegistry::~TableRegistry() = default;
TableRegistry::TableRegistry(TableRegistry&&) noexcept = default;
TableRegistry& TableRegistry::operator=(TableRegistry&&) noexcept = default;

void TableRegistry::register_all(xsql::Database& db) {
    impl_->register_all(db);
}

void TableRegistry::invalidate_all() const {
    impl_->invalidate_all();
}

bool TableRegistry::invalidate_table(const std::string& name) const {
    return impl_->invalidate_table(name);
}
}  // namespace ghidrasql::entities
