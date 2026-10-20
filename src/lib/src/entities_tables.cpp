// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "internal/entities_detail.hpp"

#include <xsql/json.hpp>
#include <xsql/runtime_settings.hpp>
#include <xsql/runtime_settings_table.hpp>
#include <xsql/interruption.hpp>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <initializer_list>
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

#include "true_believers.h"  // hidden easter-egg table; decoder vendored in-tree

namespace ghidrasql::entities {

// Helper: build a write-error message, appending source detail if available.
inline void report_write_error(
    const std::shared_ptr<Source>& source,
    const std::string& message) {
    auto detail = source->last_error();
    xsql::set_vtab_error(detail.empty() ? message : message + ": " + detail);
}

// A false read can also mean that an optional source surface is unsupported.
// Preserve that legacy empty-result behavior unless the source supplied an
// actual failure detail.
inline void report_read_error_if_any(
    const std::shared_ptr<Source>& source,
    const std::string& message) {
    auto detail = source->last_error();
    if (!detail.empty()) {
        xsql::set_vtab_error(message + ": " + detail);
    }
}

// Row ids for rows identified by (address, slot): the n-th symbol, comment,
// bookmark, data item or breakpoint at an address, or the n-th local or
// decompiler comment of a function.
//
// An id is packed as address * slots + slot when that stays inside
// [-2^62, 2^62) -- every canonical 48-bit user or kernel address does for the
// slot counts used here. Any other address (a 64-bit space such as a PPC64
// kernel at 0xC000000000000000, or anything else past the packing's reach)
// gets a key in [2^62, 2^63), handed out on first use and never reused, so its
// id still decodes to exactly the address and slot it was made from. Packing
// every address overflowed for |address| >= 2^63 / slots: an UPDATE by row id
// then decoded to another address, and a DELETE removed a different row.
class AddressSlotRowIds {
public:
    explicit AddressSlotRowIds(std::int64_t slots)
        : slots_(slots), limit_(kFirstKey / slots) {}

    std::int64_t encode(std::int64_t address, std::size_t slot) {
        if (address > -limit_ && address < limit_ &&
            slot < static_cast<std::size_t>(slots_)) {
            return address * slots_ + static_cast<std::int64_t>(slot);
        }
        std::lock_guard<std::mutex> lock(mu_);
        const auto pair = std::make_pair(address, slot);
        auto it = keys_.find(pair);
        if (it != keys_.end()) {
            return it->second;
        }
        const std::int64_t key = kFirstKey + static_cast<std::int64_t>(pairs_.size());
        pairs_.push_back(pair);
        keys_.emplace(pair, key);
        return key;
    }

    bool decode(std::int64_t rowid, std::int64_t& address, std::size_t& slot) const {
        if (rowid >= kFirstKey) {
            std::lock_guard<std::mutex> lock(mu_);
            const auto index = static_cast<std::size_t>(rowid - kFirstKey);
            if (index >= pairs_.size()) {
                return false;
            }
            address = pairs_[index].first;
            slot = pairs_[index].second;
            return true;
        }
        // Euclidean division: a packed high-half address is negative, and C++
        // division truncates toward zero.
        std::int64_t quotient = rowid / slots_;
        std::int64_t remainder = rowid % slots_;
        if (remainder < 0) {
            --quotient;
            remainder += slots_;
        }
        address = quotient;
        slot = static_cast<std::size_t>(remainder);
        return true;
    }

private:
    static constexpr std::int64_t kFirstKey = std::int64_t{1} << 62;

    struct PairHash {
        std::size_t operator()(const std::pair<std::int64_t, std::size_t>& p) const {
            return std::hash<std::int64_t>()(p.first) * 31u + std::hash<std::size_t>()(p.second);
        }
    };

    const std::int64_t slots_;
    const std::int64_t limit_;
    mutable std::mutex mu_;
    std::unordered_map<std::pair<std::int64_t, std::size_t>, std::int64_t, PairHash> keys_;
    std::vector<std::pair<std::int64_t, std::size_t>> pairs_;
};

// One id space per slot count; a pair keeps its id for the life of the process.
inline AddressSlotRowIds& address_row_ids() {      // symbols, bookmarks, data items, breakpoints
    static AddressSlotRowIds ids(0x1000);
    return ids;
}
inline AddressSlotRowIds& comment_row_ids() {      // comment kinds at an address
    static AddressSlotRowIds ids(0x10);
    return ids;
}
inline AddressSlotRowIds& function_slot_row_ids() {  // locals / decompiler comments of a function
    static AddressSlotRowIds ids(0x10000);
    return ids;
}

// A row carrying the key its table reports as rowid. libxsql requires rowid()
// with row_lookup(): a full or index scan must report the same key the
// table's filter iterators report and row_lookup() decodes, never a cache
// position (read as a key, a position names another row -- on an image at
// address 0 an existing one).
template <typename Row>
struct KeyedRow : Row {
    std::int64_t row_key = 0;
};

template <typename Row>
inline KeyedRow<Row> keyed_row(Row row, std::int64_t key) {
    KeyedRow<Row> keyed;
    static_cast<Row&>(keyed) = std::move(row);
    keyed.row_key = key;
    return keyed;
}

// Key a full read the way the table's addr filter keys a point read: a row's
// slot is its index among the rows at its address. The host lists one
// address's rows in the same order for a point query as within a full scan
// (both filter the same iterator), so the key names the same row either way.
// A full scan's rows the point read cannot see (Ghidra's external symbols,
// appended after every memory row with their EXTERNAL-space offset as the
// address) get slots past the point read's rows, so decoding their keys finds
// nothing rather than a memory row (the statement's scan record still holds
// them; names refuses to write an external row).
template <typename Row>
inline std::vector<std::pair<std::int64_t, Row>> key_by_address_slot(std::vector<Row> rows,
                                                                     AddressSlotRowIds& ids) {
    std::unordered_map<std::int64_t, std::size_t> next_slot;
    std::vector<std::pair<std::int64_t, Row>> out;
    out.reserve(rows.size());
    for (auto& row : rows) {
        const std::int64_t address = row.address;
        const std::int64_t key = ids.encode(address, next_slot[address]++);
        out.emplace_back(key, std::move(row));
    }
    return out;
}

template <typename Row>
inline std::vector<KeyedRow<Row>> keyed_rows_of(
    const std::vector<std::pair<std::int64_t, Row>>& indexed) {
    std::vector<KeyedRow<Row>> out;
    out.reserve(indexed.size());
    for (const auto& entry : indexed) {
        out.push_back(keyed_row(entry.second, entry.first));
    }
    return out;
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

    // Record the rows a scan emitted, by key. Every scan of the statement adds
    // to the record (a self-join scans twice); a key scanned again keeps its
    // latest row. The record lives for one statement (QueryStateGuard).
    void store(std::vector<std::pair<std::int64_t, RowData>> indexed) {
        std::lock_guard<std::mutex> lk(mu);
        const auto by_key = [](const auto& a, const auto& b) { return a.first < b.first; };
        if (!valid || rows.empty()) {
            rows = std::move(indexed);
        } else {
            // Newer rows first so the stable sort + unique keeps them.
            indexed.insert(indexed.end(), std::make_move_iterator(rows.begin()),
                           std::make_move_iterator(rows.end()));
            rows = std::move(indexed);
        }
        std::stable_sort(rows.begin(), rows.end(), by_key);
        rows.erase(std::unique(rows.begin(), rows.end(),
                               [](const auto& a, const auto& b) { return a.first == b.first; }),
                   rows.end());
        valid = true;
    }

    bool lookup(std::int64_t rowid, RowData& out) const {
        std::lock_guard<std::mutex> lk(mu);
        if (!valid) {
            return false;
        }
        auto it = std::lower_bound(
            rows.begin(), rows.end(), rowid,
            [](const auto& entry, std::int64_t key) { return entry.first < key; });
        if (it != rows.end() && it->first == rowid) {
            out = it->second;
            return true;
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

// Rows keyed (address, index at the address) or (function, index in it) shift
// when an earlier row of the same group is deleted: in a multi-row DELETE the
// next key would decode to the row after its own. Each such table records the
// rows its scans emitted, and row_lookup() resolves a key from that record
// first, so every write in the statement acts on the row it read.
struct QueryScopeState {
    QueryScopedSearchRows search_index_rows;
    QueryScopedIndexedRows<model::FunctionLocalRow> function_local_rows;
    QueryScopedIndexedRows<model::DecompLvarRow> decomp_lvar_rows;
    QueryScopedIndexedRows<model::SymbolRow> name_rows;
    QueryScopedIndexedRows<model::CommentRow> comment_rows;
    QueryScopedIndexedRows<model::DecompCommentRow> decomp_comment_rows;
    QueryScopedIndexedRows<model::BreakpointRow> breakpoint_rows;
    QueryScopedIndexedRows<model::BookmarkRow> bookmark_rows;

    void reset_all() {
        search_index_rows.reset();
        function_local_rows.reset();
        decomp_lvar_rows.reset();
        name_rows.reset();
        comment_rows.reset();
        decomp_comment_rows.reset();
        breakpoint_rows.reset();
        bookmark_rows.reset();
    }

    void reset_for_table(const std::string& name) {
        if (name == "search_index") {
            search_index_rows.reset();
        } else if (name == "function_locals") {
            function_local_rows.reset();
        } else if (name == "decomp_lvars") {
            decomp_lvar_rows.reset();
        } else if (name == "names") {
            name_rows.reset();
        } else if (name == "comments") {
            comment_rows.reset();
        } else if (name == "decomp_comments") {
            decomp_comment_rows.reset();
        } else if (name == "breakpoints") {
            breakpoint_rows.reset();
        } else if (name == "bookmarks") {
            bookmark_rows.reset();
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

// Format an address as lowercase 0x-hex for error/diagnostic messages. std::to_string
// prints DECIMAL, so the widespread "0x" + std::to_string(addr) mis-rendered addresses
// (e.g. 0x140001195 shown as "0x5368713621", its decimal value) -- use this instead.
inline std::string addr_hex(std::int64_t address) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(address));
    return buf;
}

// Every row of a per-function table, keyed as its func_addr filter keys it:
// function_slot_row_ids().encode(func_addr, index in derive_for(func_addr)).
// The full scan, the filter and row_lookup() therefore all name a row the same
// way. (These keys used to be 0..N-1, which row_lookup() -- when the statement
// store missed -- decoded as (0, i): function 0's locals on an image at 0.)
template <typename Row, typename DeriveAll, typename DeriveFor>
inline std::vector<std::pair<std::int64_t, Row>> derive_indexed_rows(
    const std::shared_ptr<Source>& source,
    DeriveAll derive_all,
    DeriveFor derive_for)
{
    std::vector<model::FunctionRow> functions;
    if (!source->read_functions(functions) || functions.empty()) {
        // No function list: group the source's own rows by function, in order.
        auto rows = derive_all(source);
        std::unordered_map<std::int64_t, std::size_t> next_slot;
        std::vector<std::pair<std::int64_t, Row>> indexed;
        indexed.reserve(rows.size());
        for (auto& row : rows) {
            const std::int64_t key =
                function_slot_row_ids().encode(row.func_addr, next_slot[row.func_addr]++);
            indexed.emplace_back(key, std::move(row));
        }
        return indexed;
    }
    std::vector<std::pair<std::int64_t, Row>> indexed;
    for (const auto& fn : functions) {
        auto rows = derive_for(source, fn.address);
        for (std::size_t i = 0; i < rows.size(); ++i) {
            indexed.emplace_back(function_slot_row_ids().encode(fn.address, i),
                                 std::move(rows[i]));
        }
    }
    return indexed;
}

// decomp_comments keys a row (f, i): i is its index in
// derive_decomp_comment_rows_for(f) -- every comment inside f's body, in SQL
// order of address, one address's kinds in listing order. A full scan reads
// each comment once, attributed to one owner, so rebuild each owner's list
// from that read (no per-function reads) and key the row by its place in it.
// A comment in no function is what derive_decomp_comment_rows_for(address)
// lists at its own address: key it there. A row that fits neither (the
// source's owner disagrees with the function bodies) gets a key past every
// list, which resolves to nothing rather than to another comment.
inline std::vector<std::pair<std::int64_t, model::DecompCommentRow>> key_decomp_comment_rows(
    const std::shared_ptr<Source>& source, std::vector<model::DecompCommentRow> rows)
{
    std::vector<model::FunctionRow> functions;
    if (!source->read_functions(functions)) {
        functions.clear();
    }
    std::unordered_map<std::int64_t, const model::FunctionRow*> by_entry;
    by_entry.reserve(functions.size());
    for (const auto& fn : functions) {
        by_entry.emplace(fn.address, &fn);
    }

    // Row indices in SQL (signed) address order; a stable sort keeps one
    // address's kinds in the order the source listed them.
    struct Ref {
        std::int64_t address = 0;
        std::size_t index = 0;
    };
    std::vector<Ref> order;
    order.reserve(rows.size());
    for (std::size_t i = 0; i < rows.size(); ++i) {
        order.push_back(Ref{rows[i].address, i});
    }
    std::stable_sort(order.begin(), order.end(),
                     [](const Ref& a, const Ref& b) { return a.address < b.address; });

    std::vector<std::optional<std::int64_t>> keys(rows.size());
    std::unordered_set<std::int64_t> owners_done;
    for (const auto& row : rows) {
        const std::int64_t owner = row.func_addr;
        auto fn = by_entry.find(owner);
        if (fn == by_entry.end() || !owners_done.insert(owner).second) {
            continue;
        }
        std::vector<Ref> list;
        read_function_body_runs(*fn->second, list,
            [&](std::int64_t first, std::int64_t last, std::vector<Ref>& part) {
                auto lo = std::lower_bound(order.begin(), order.end(), first,
                    [](const Ref& r, std::int64_t v) { return r.address < v; });
                auto hi = std::upper_bound(order.begin(), order.end(), last,
                    [](std::int64_t v, const Ref& r) { return v < r.address; });
                part.assign(lo, hi);
                return true;
            });
        for (std::size_t i = 0; i < list.size(); ++i) {
            if (rows[list[i].index].func_addr == owner) {
                keys[list[i].index] = function_slot_row_ids().encode(owner, i);
            }
        }
    }

    std::unordered_map<std::int64_t, std::size_t> next_slot;
    std::size_t unplaced = 0;
    std::vector<std::pair<std::int64_t, model::DecompCommentRow>> out;
    out.reserve(rows.size());
    for (std::size_t i = 0; i < rows.size(); ++i) {
        std::int64_t key = 0;
        if (keys[i]) {
            key = *keys[i];
        } else if (!by_entry.count(rows[i].address)) {
            key = function_slot_row_ids().encode(rows[i].address, next_slot[rows[i].address]++);
        } else {
            key = function_slot_row_ids().encode(rows[i].address, 0x10000 + unplaced++);
        }
        out.emplace_back(key, std::move(rows[i]));
    }
    return out;
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

// Comment writes try more than one kind (the row's own kind, then the
// eol/repeatable pair a source without by-kind writes understands). Each
// failed attempt records its error, so a later attempt that succeeds must
// clear it rather than leave a stale vtab error behind. When every attempt
// fails, the first recorded error is the one reported: it names the row's own
// kind, which is the comment the statement meant.
inline bool first_comment_write_that_succeeds(
    const std::string& context,
    std::initializer_list<std::function<bool()>> attempts)
{
    std::string first_error;
    for (const auto& attempt : attempts) {
        xsql::clear_vtab_error();
        if (attempt()) {
            xsql::clear_vtab_error();
            return true;
        }
        if (first_error.empty()) {
            first_error = xsql::get_vtab_error();
        }
    }
    xsql::set_vtab_error(first_error.empty() ? context : context + ": " + first_error);
    return false;
}

// set_comment / delete_comment take only a repeatable flag, so they name the
// eol or the repeatable comment. A pre, post or plate row must never fall back
// to them: that would write or delete a different comment at the address.
inline bool comment_kind_has_flag_form(const std::string& kind) {
    const auto k = lower_copy(kind);
    return k != "pre" && k != "post" && k != "plate";
}

// Deletes the comment a decomp_comments row shows: by its kind, then (eol and
// repeatable rows only) by the flag form, for a source without by-kind deletes.
inline bool delete_decomp_comment(
    const std::shared_ptr<Source>& source,
    const model::DecompCommentRow& row,
    const std::string& context)
{
    return first_comment_write_that_succeeds(
        context,
        {[&] { return source->delete_comment_by_kind(row.address, row.source); },
         [&] {
             return comment_kind_has_flag_form(row.source) &&
                 source->delete_comment(
                     row.address, decomp_comment_source_is_repeatable(row.source));
         }});
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
            report_write_error(source, "INSERT INTO " + table_name +
                " failed: set_comment_by_kind at " + addr_hex(address));
            return false;
        }
        return true;
    }

    if (!comment_opt) {
        xsql::set_vtab_error("INSERT INTO " + table_name + " requires comment or source");
        return false;
    }

    if (!source->set_comment(address, *comment_opt, repeatable)) {
        report_write_error(source, "INSERT INTO " + table_name +
            " failed: set_comment at " + addr_hex(address));
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
        case 1: ctx.result_int64(r.length); return;
        case 2: ctx.result_text(r.type); return;
        case 3:
            switch (classify_string_encoding(r.encoding)) {
                case StringEncClass::kUtf16: ctx.result_text("utf16"); return;
                case StringEncClass::kUtf32: ctx.result_text("utf32"); return;
                default: ctx.result_text("ascii"); return;
            }
        case 4:
            switch (classify_string_encoding(r.encoding)) {
                case StringEncClass::kUtf16: ctx.result_int(2); return;
                case StringEncClass::kUtf32: ctx.result_int(4); return;
                default: ctx.result_int(1); return;
            }
        case 5:
            switch (classify_string_encoding(r.encoding)) {
                case StringEncClass::kUtf16: ctx.result_text("2-byte"); return;
                case StringEncClass::kUtf32: ctx.result_text("4-byte"); return;
                default: ctx.result_text("1-byte"); return;
            }
        case 6: ctx.result_int(0); return;
        case 7: ctx.result_text("linear"); return;
        case 8: ctx.result_text(r.encoding); return;
        case 9: ctx.result_text(r.content); return;
        default: ctx.result_null(); return;
    }
}

inline void column_string_ref(xsql::FunctionContext& ctx, int col,
                              const model::StringRefRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.string_addr); return;
        case 1: ctx.result_text(r.string_value); return;
        case 2: ctx.result_int64(r.string_length); return;
        case 3: ctx.result_int64(r.ref_addr); return;
        case 4: ctx.result_int64(r.func_addr); return;
        case 5: ctx.result_text(r.func_name); return;
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
    if (row.address != func_addr) {
        return std::nullopt;
    }
    return row;
}

inline std::vector<model::FunctionRow> find_function_rows_by_name(
    const std::shared_ptr<Source>& source,
    const std::string& name) {
    std::vector<model::FunctionRow> functions;
    if (!source->read_functions(functions)) {
        return {};
    }

    std::vector<model::FunctionRow> matched;
    matched.reserve(functions.size());
    for (const auto& fn : functions) {
        if (fn.name == name) {
            matched.push_back(fn);
        }
    }
    return matched;
}

inline void column_function(xsql::FunctionContext& ctx, int col, const model::FunctionRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_text(r.name); return;
        case 2: ctx.result_int64(r.size); return;
        case 3: ctx.result_int64(r.end_ea); return;
        case 4: ctx.result_int64(r.flags); return;
        case 5: ctx.result_text(r.namespace_name); return;
        case 6: ctx.result_text(r.signature); return;
        case 7: ctx.result_text(function_return_type(r)); return;
        case 8: ctx.result_int64(function_arg_count(r)); return;
        case 9: ctx.result_text(function_calling_convention(r)); return;
        case 10: ctx.result_int(type_is_pointer_compat(function_return_type(r)) ? 1 : 0); return;
        case 11: ctx.result_int(type_is_void_compat(function_return_type(r)) ? 1 : 0); return;
        case 12: ctx.result_int(type_is_int_compat(function_return_type(r)) ? 1 : 0); return;
        case 13: ctx.result_int(type_is_integral_compat(function_return_type(r)) ? 1 : 0); return;
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

inline void column_xref_index(xsql::FunctionContext& ctx, int col,
                              const model::XrefIndexRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.from_ea); return;
        case 1: ctx.result_int64(r.to_ea); return;
        case 2: ctx.result_int64(r.src_func_addr); return;
        case 3: ctx.result_int64(r.dst_func_addr); return;
        case 4: ctx.result_text(r.kind); return;
        case 5: ctx.result_int(r.is_code); return;
        case 6: ctx.result_int(r.is_data); return;
        default: ctx.result_null(); return;
    }
}

// Column emitter for the source-bounded call_edges equality-filter paths.
// Column order MUST match define_call_edges' .column_*() declarations exactly.
inline void column_call_edge(xsql::FunctionContext& ctx, int col,
                             const model::CallEdgeRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.src_func_addr); return;
        case 1: ctx.result_text(r.src_func_name); return;
        case 2: ctx.result_int64(r.call_site); return;
        case 3: ctx.result_int64(r.dst_addr); return;
        case 4: ctx.result_int64(r.dst_func_addr); return;
        case 5: ctx.result_text(r.dst_func_name); return;
        case 6: ctx.result_text(r.kind); return;
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
        case 6: ctx.result_int64(r.func_addr); return;
        default: ctx.result_null(); return;
    }
}

// Column emitter for the constants func_addr filter_eq path. Column order MUST
// match define_constants' .column_*() declarations exactly.
inline void column_constant(xsql::FunctionContext& ctx, int col,
                            const model::ConstantRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;
        case 1: ctx.result_int64(r.func_addr); return;
        case 2: ctx.result_int64(r.value); return;
        case 3: ctx.result_int64(r.width); return;
        case 4: ctx.result_text(r.repr); return;
        case 5: ctx.result_text(r.source_kind); return;
        default: ctx.result_null(); return;
    }
}

inline void column_instruction_operand(xsql::FunctionContext& ctx, int col,
                                       const model::InstructionOperandRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.address); return;       // addr
        case 1: ctx.result_int64(r.func_addr); return;     // func_addr
        case 2: ctx.result_int(r.operand_index); return;   // operand_index
        case 3: ctx.result_text(r.text); return;           // text
        case 4: ctx.result_text(r.type_name); return;      // type_name
        case 5: ctx.result_text(r.ref_type); return;       // ref_type (ghidra extra)
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
        case 4: ctx.result_text(r.prototype); return;
        case 5: ctx.result_int(r.completed); return;
        case 6: ctx.result_int(r.is_fallback); return;
        case 7: ctx.result_text(r.error_message); return;
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
        case 6: ctx.result_text(r.func_name); return;
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

// Column emitter for the function_params filter_eq path. Column order MUST
// match define_function_params' .column_*() declarations exactly.
inline void column_function_param(xsql::FunctionContext& ctx, int col, const model::FunctionParamRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.func_addr); return;
        case 1: ctx.result_int64(r.ordinal); return;
        case 2: ctx.result_text(r.param_name); return;
        case 3: ctx.result_text(r.param_type); return;
        case 4: ctx.result_text(r.storage); return;
        case 5: ctx.result_int(r.is_user_named); return;
        default: ctx.result_null(); return;
    }
}

// Column emitter for the function_frames filter_eq path. Column order MUST match
// define_function_frames' .column_*() declarations exactly. saved_reg_size,
// stack_base_reg and has_frame_pointer emit SQL NULL when unknown.
inline void column_function_frame(xsql::FunctionContext& ctx, int col, const model::FunctionFrameRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.func_addr); return;
        case 1: ctx.result_int64(r.frame_size); return;
        case 2: ctx.result_int64(r.arg_size); return;
        case 3: ctx.result_int64(r.local_size); return;
        case 4:
            if (r.saved_reg_size_known) ctx.result_int(static_cast<int>(r.saved_reg_size));
            else ctx.result_null();
            return;
        case 5:
            if (!r.stack_base_reg.empty()) ctx.result_text(r.stack_base_reg);
            else ctx.result_null();
            return;
        case 6:
            if (r.has_frame_pointer >= 0) ctx.result_int(r.has_frame_pointer);
            else ctx.result_null();
            return;
        default: ctx.result_null(); return;
    }
}

// Column emitter for the stack_vars filter_eq path. Column order MUST match
// define_stack_vars' .column_*() declarations exactly.
inline void column_stack_var(xsql::FunctionContext& ctx, int col, const model::StackVarRow& r) {
    switch (col) {
        case 0: ctx.result_int64(r.func_addr); return;
        case 1: ctx.result_text(r.var_id); return;
        case 2: ctx.result_text(r.name); return;
        case 3: ctx.result_text(r.var_type); return;
        case 4: ctx.result_int64(r.stack_offset); return;
        case 5: ctx.result_int64(r.size); return;
        case 6: ctx.result_int(r.is_param); return;
        default: ctx.result_null(); return;
    }
}

inline xsql::CachedTableDef<model::FunctionRow> define_funcs(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::FunctionRow>("funcs")
        .no_shared_cache()
        // Estimates run during SQLite planning. Reading the live table here
        // performed one complete RPC scan before cache_builder performed the same
        // scan again. A stable heuristic is cheaper and sufficient for planning.
        .estimate_rows([]() { return size_t(10000); })
        .cache_builder([source](std::vector<model::FunctionRow>& out) {
            if (!source->read_functions(out)) {
                out.clear();
            }
        })
        .column_int64("addr", [](const model::FunctionRow& r) { return r.address; })
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
                        "UPDATE funcs.name failed at " + addr_hex(row.address));
                    return false;
                }
                row.name = next;
                return true;
            })
        .column_int64("size", [](const model::FunctionRow& r) { return r.size; })
        .column_int64("end_addr", [](const model::FunctionRow& r) { return r.end_ea; })
        .column_int64("flags", [](const model::FunctionRow& r) { return r.flags; })
        .column_text("namespace", [](const model::FunctionRow& r) { return r.namespace_name; })
        .column_text_rw(
            "prototype",
            [](const model::FunctionRow& r) { return r.signature; },
            [source](model::FunctionRow& row, const char* prototype) {
                const std::string next = prototype ? prototype : "";
                if (row.signature == next) {
                    return true;
                }
                if (!source->set_function_signature(row.address, next)) {
                    report_write_error(
                        source,
                        "UPDATE funcs.prototype failed at " + addr_hex(row.address));
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
        // The row id is the address everywhere: full and index scans (rowid),
        // the addr filter and row_lookup. Negative at or above 2^63.
        .rowid([](const model::FunctionRow& r) { return r.address; })
        .row_lookup([source](model::FunctionRow& row, std::int64_t raw_rowid) {
            auto matched = find_function_row_by_address(source, raw_rowid);
            if (!matched.has_value()) {
                return false;
            }
            row = *matched;
            return true;
        })
        .filter_eq("addr",
            [source](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<std::pair<std::int64_t, model::FunctionRow>> rows;
                if (auto row = find_function_row_by_address(source, func_addr); row.has_value()) {
                    rows.emplace_back(func_addr, *row);
                }
                return std::make_unique<IndexedOwnedRowIterator<model::FunctionRow>>(
                    std::move(rows),
                    column_function);
            }, 2.0, 1.0)
        .index_on("addr", [](const model::FunctionRow& r) { return r.address; })
        .index_on("end_addr", [](const model::FunctionRow& r) { return r.end_ea; })
        .constraint_cache_filter(
            {xsql::required_le("addr", "function start upper bound required"),
             xsql::required_gt("end_addr", "function end lower bound required")},
            1.0,
            1.0)
        .build();
}

inline xsql::CachedTableDef<model::FunctionRow> define_leaf_funcs(
    const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::FunctionRow>("leaf_funcs")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(2000); })
        .cache_builder([source](std::vector<model::FunctionRow>& out) {
            if (!source->read_leaf_functions(out)) {
                out.clear();
            }
        })
        .column_int64("addr", [](const model::FunctionRow& r) { return r.address; })
        .column_text("name", [](const model::FunctionRow& r) { return r.name; })
        .column_int64("size", [](const model::FunctionRow& r) { return r.size; })
        .column_int64("end_addr", [](const model::FunctionRow& r) { return r.end_ea; })
        .column_text("namespace", [](const model::FunctionRow& r) { return r.namespace_name; })
        .column_text("prototype", [](const model::FunctionRow& r) { return r.signature; })
        .index_on("addr", [](const model::FunctionRow& r) { return r.address; })
        .build();
}

// start_addr / end_addr of a block INSERT. Both are unsigned 64-bit addresses
// bit-cast into SQL (an address >= 2^63 is a negative INTEGER), and end_addr is
// exclusive and modulo 2^64: 0 ends the block at 0xFFFFFFFFFFFFFFFF, the last
// address. A value must be an INTEGER: a decimal literal >= 2^63 is a REAL in
// SQLite, which would otherwise clamp to 0x7FFFFFFFFFFFFFFF.
inline bool block_bounds_args(int argc, xsql::FunctionArg* argv, const char* table,
                              std::int64_t& start, std::int64_t& end) {
    const char* columns[2] = {"start_addr", "end_addr"};
    std::int64_t values[2] = {0, 0};
    for (int i = 0; i < 2; ++i) {
        if (arg_is_missing(argc, argv, i)) {
            xsql::set_vtab_error(std::string(table) + ": INSERT requires start_addr and end_addr");
            return false;
        }
        const std::optional<std::int64_t> value = xsql::exact_int64(argv[i]);
        if (!value) {
            xsql::set_vtab_error(std::string(table) + ": " + columns[i] +
                                 " must be an INTEGER address (write one >= 2^63 as a hex "
                                 "literal or a negative decimal)");
            return false;
        }
        values[i] = *value;
    }
    start = values[0];
    end = values[1];
    if (address_span_size(start, end) == 0) {
        xsql::set_vtab_error(std::string(table) +
                             ": end_addr must be above start_addr (unsigned; an address >= "
                             "2^63 is a negative INTEGER; end_addr 0 is the end of the "
                             "address space)");
        return false;
    }
    return true;
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
        // Canonical address columns. start_addr is writable: UPDATE rebases
        // (moves) the underlying Ghidra memory block.
        .column_int64_rw("start_addr",
            [](const model::SegmentRow& r) { return r.start_ea; },
            [source](model::SegmentRow& row, std::int64_t new_start) -> bool {
                if (new_start == row.start_ea) {
                    return true;
                }
                if (!source->move_memory_block(row.start_ea, new_start)) {
                    report_write_error(source, "UPDATE segments.start_addr (rebase) failed");
                    return false;
                }
                // Same size, new start; the end stays modulo 2^64.
                const std::uint64_t size = address_span_size(row.start_ea, row.end_ea);
                row.start_ea = new_start;
                row.end_ea = static_cast<std::int64_t>(static_cast<std::uint64_t>(new_start) + size);
                return true;
            })
        // end_addr / name / perm all route through the one SetMemoryBlockAttributes RPC,
        // each sending only its own field so an UPDATE of one cannot reset the others.
        .column_int64_rw("end_addr",
            [](const model::SegmentRow& r) { return r.end_ea; },
            [source](model::SegmentRow& row, std::int64_t new_end) -> bool {
                if (new_end == row.end_ea) {
                    return true;
                }
                if (!source->set_memory_block_attributes(row.start_ea, std::nullopt, std::nullopt,
                                                         new_end)) {
                    report_write_error(source, "UPDATE segments.end_addr (resize) failed");
                    return false;
                }
                row.end_ea = new_end;
                return true;
            })
        .column_text_rw("name",
            [](const model::SegmentRow& r) { return r.name; },
            [source](model::SegmentRow& row, const std::string& new_name) -> bool {
                if (new_name == row.name) {
                    return true;
                }
                if (!source->set_memory_block_attributes(row.start_ea, new_name, std::nullopt,
                                                         std::nullopt)) {
                    report_write_error(source, "UPDATE segments.name failed");
                    return false;
                }
                row.name = new_name;
                return true;
            })
        .column_text("class", [](const model::SegmentRow& r) { return r.segment_class; })
        .column_int_rw("perm",
            [](const model::SegmentRow& r) { return r.perm; },
            [source](model::SegmentRow& row, int new_perm) -> bool {
                if (new_perm == row.perm) {
                    return true;
                }
                if (!source->set_memory_block_attributes(row.start_ea, std::nullopt, new_perm,
                                                         std::nullopt)) {
                    report_write_error(source, "UPDATE segments.perm failed");
                    return false;
                }
                row.perm = new_perm;
                return true;
            })
        .column_int("bitness", [](const model::SegmentRow& r) { return r.bitness; })
        .index_on("start_addr", [](const model::SegmentRow& r) { return r.start_ea; })
        .deletable([source](model::SegmentRow& row) -> bool {
            if (!source->remove_memory_block(row.start_ea)) {
                report_write_error(source, "DELETE FROM segments failed");
                return false;
            }
            return true;
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) -> bool {
            // cols: 0 start_addr, 1 end_addr, 2 name, 3 class, 4 perm.
            std::int64_t start = 0;
            std::int64_t end = 0;
            if (!block_bounds_args(argc, argv, "segments", start, end)) {
                return false;
            }
            const std::string name = arg_text_or(argc, argv, 2, "");
            const int perm = static_cast<int>(arg_int64_opt(argc, argv, 4).value_or(6));
            // Uninitialized block (no file backing), e.g. an SRAM region.
            if (!source->create_memory_block(start, end, name, perm, /*initialized=*/false)) {
                report_write_error(source, "INSERT INTO segments failed");
                return false;
            }
            return true;
        })
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
        // Canonical address columns. start_addr is writable: UPDATE rebases
        // (moves) the underlying Ghidra memory block.
        .column_int64_rw("start_addr",
            [](const model::MemoryBlockRow& r) { return r.start_ea; },
            [source](model::MemoryBlockRow& row, std::int64_t new_start) -> bool {
                if (new_start == row.start_ea) {
                    return true;
                }
                if (!source->move_memory_block(row.start_ea, new_start)) {
                    report_write_error(source, "UPDATE memory_blocks.start_addr (rebase) failed");
                    return false;
                }
                // Same size, new start; the end stays modulo 2^64.
                const std::uint64_t size = address_span_size(row.start_ea, row.end_ea);
                row.start_ea = new_start;
                row.end_ea = static_cast<std::int64_t>(static_cast<std::uint64_t>(new_start) + size);
                return true;
            })
        .column_int64("end_addr", [](const model::MemoryBlockRow& r) { return r.end_ea; })
        .column_text("name", [](const model::MemoryBlockRow& r) { return r.name; })
        .column_text("class", [](const model::MemoryBlockRow& r) { return r.block_class; })
        .column_int("perm", [](const model::MemoryBlockRow& r) { return r.perm; })
        .column_int("bitness", [](const model::MemoryBlockRow& r) { return r.bitness; })
        .column_int64("size", [](const model::MemoryBlockRow& r) { return r.size; })
        .column_int("is_read", [](const model::MemoryBlockRow& r) { return r.is_read; })
        .column_int("is_write", [](const model::MemoryBlockRow& r) { return r.is_write; })
        .column_int("is_exec", [](const model::MemoryBlockRow& r) { return r.is_exec; })
        .index_on("start_addr", [](const model::MemoryBlockRow& r) { return r.start_ea; })
        .deletable([source](model::MemoryBlockRow& row) -> bool {
            if (!source->remove_memory_block(row.start_ea)) {
                report_write_error(source, "DELETE FROM memory_blocks failed");
                return false;
            }
            return true;
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) -> bool {
            // cols: 0 start_addr, 1 end_addr, 2 name, 3 class, 4 perm,
            //       5 bitness, 6 size, 7 is_read, 8 is_write, 9 is_exec.
            std::int64_t start = 0;
            std::int64_t end = 0;
            if (!block_bounds_args(argc, argv, "memory_blocks", start, end)) {
                return false;
            }
            const std::string name = arg_text_or(argc, argv, 2, "");
            const int perm = static_cast<int>(arg_int64_opt(argc, argv, 4).value_or(6));
            if (!source->create_memory_block(start, end, name, perm, /*initialized=*/false)) {
                report_write_error(source, "INSERT INTO memory_blocks failed");
                return false;
            }
            return true;
        })
        .build();
}

// Fold pushed-down addr constraints (EQ / GE / GT / LE / LT) into one
// inclusive signed window. `empty` marks a provably-empty result set.
struct MemoryBytesWindow {
    std::int64_t lo = std::numeric_limits<std::int64_t>::min();
    std::int64_t hi = std::numeric_limits<std::int64_t>::max();
    bool empty = false;
};

// The addr window a point or range plan consumed. The constraints are omit=1,
// so each is compared the way SQLite compares the INTEGER addr column
// (xsql::Int64KeyRange): `addr = 4096.5` and `addr = NULL` match nothing and
// `addr >= 4095.5` starts at 4096 -- as_int64() truncated all three.
inline MemoryBytesWindow memory_bytes_window_from_args(
    const std::vector<xsql::GeneratorConstraintArg>& args)
{
    xsql::Int64KeyRange range;
    for (const auto& arg : args) {
        if (arg.op == xsql::ConstraintOp::Like) continue;
        range.constrain(arg.op, arg.value);
    }
    MemoryBytesWindow w;
    if (range.empty()) {
        w.empty = true;
        w.lo = 1;
        w.hi = 0;  // lo > hi: the generator yields nothing
        return w;
    }
    w.lo = range.lower();
    w.hi = range.upper();
    return w;
}

inline xsql::GeneratorTableDef<model::MemoryByteRow> define_memory_bytes(const std::shared_ptr<Source>& source) {
    // memory_bytes is a streaming GENERATOR table (the idasql `bytes` pattern)
    // — nothing is ever materialized. A point (`WHERE addr = X`) or range
    // (`BETWEEN` / `>=` / `<`) predicate pushes down into a windowed
    // derivation (make_memory_bytes_generator) that pages only the requested
    // bytes (32 KiB ReadBytes pages) and fetches only that window's
    // attribution items via the *_in_range Source readers; an unconstrained
    // scan still yields EVERY mapped byte in ascending addr order but streams
    // it in O(page) memory, so LIMIT terminates early and a huge uninitialized
    // block (e.g. a 512 MB .bss) costs nothing beyond the rows actually
    // consumed. Uninitialized-block bytes surface value NULL /
    // is_initialized=0 from block metadata alone (never read — the host errors
    // on uninitialized memory by contract); `WHERE is_initialized = 1`
    // reproduces the legacy initialized-only view. rowid == addr, which feeds
    // the row_lookup UPDATE path below.
    return xsql::generator_table<model::MemoryByteRow>("bytes")
        .estimate_rows([source]() { return estimate_memory_byte_rows(source); })
        .generator([source]() {
            return make_memory_bytes_generator(
                source,
                std::numeric_limits<std::int64_t>::min(),
                std::numeric_limits<std::int64_t>::max(),
                /*descending=*/false);
        })
        .column_int64("addr", [](const model::MemoryByteRow& r) { return r.address; })
        // `value` reads back NULL for an uninitialized byte (is_initialized=0):
        // this preserves the "byte is 0" vs "byte is unknown" distinction. A write
        // to an uninitialized byte is rejected — there is no backing storage to
        // patch until the block is initialized.
        .column_rw("value", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const model::MemoryByteRow& r) {
                if (r.is_initialized == 0) {
                    ctx.result_null();
                    return;
                }
                ctx.result_int(r.value);
            },
            [source](model::MemoryByteRow& r, xsql::FunctionArg arg) {
                if (r.is_initialized == 0) {
                    xsql::set_vtab_error(
                        "bytes.value: cannot patch an uninitialized byte "
                        "(is_initialized = 0)");
                    return false;
                }
                if (arg.is_null()) {
                    xsql::set_vtab_error("bytes.value must be 0-255, not NULL");
                    return false;
                }
                const std::int64_t v = arg.as_int64();
                if (v < 0 || v > 255) {
                    xsql::set_vtab_error("bytes.value must be 0-255");
                    return false;
                }
                if (!source->write_byte(r.address, static_cast<std::uint8_t>(v))) {
                    report_write_error(source,
                        "UPDATE bytes.value failed at " + addr_hex(r.address));
                    return false;
                }
                r.value = static_cast<int>(v);
                r.is_printable = (v >= 0x20 && v <= 0x7E) ? 1 : 0;
                r.ascii = memory_ascii_from_value(static_cast<int>(v));
                return true;
            })
        .column_text("segment_name", [](const model::MemoryByteRow& r) { return r.segment_name; })
        .column_int64("func_addr", [](const model::MemoryByteRow& r) { return r.func_addr; })
        .column_text("source_kind", [](const model::MemoryByteRow& r) { return r.source_kind; })
        .column_int64("item_addr", [](const model::MemoryByteRow& r) { return r.item_addr; })
        .column_int64("item_offset", [](const model::MemoryByteRow& r) { return r.item_offset; })
        .column_int("is_printable", [](const model::MemoryByteRow& r) { return r.is_printable; })
        .column_text("ascii", [](const model::MemoryByteRow& r) { return r.ascii; })
        .column_int("is_initialized", [](const model::MemoryByteRow& r) { return r.is_initialized; })
        // UPDATE path: rowid == addr; resolve the single-byte window so the
        // value setter sees the byte's real is_initialized state.
        .row_lookup([source](model::MemoryByteRow& row, std::int64_t rowid) {
            if (!lookup_memory_byte_row(source, rowid, row)) {
                xsql::set_vtab_error(
                    "bytes: no mapped byte at " + addr_hex(rowid));
                return false;
            }
            return true;
        })
        // Point read: `WHERE addr = X` derives exactly one byte's window.
        .constraint_filter(
            {xsql::required_eq("addr", "")},
            [source](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<model::MemoryByteRow>> {
                const auto w = memory_bytes_window_from_args(args);
                return make_memory_bytes_generator(source, w.lo, w.hi, /*descending=*/false);
            },
            1.0, 1.0)
        .order_by_consumed("addr")
        // Bounded range, ascending (BETWEEN is delivered as GE+LE).
        .constraint_filter(
            {xsql::optional_ge("addr"), xsql::optional_gt("addr"),
             xsql::optional_lt("addr"), xsql::optional_le("addr")},
            [source](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<model::MemoryByteRow>> {
                const auto w = memory_bytes_window_from_args(args);
                return make_memory_bytes_generator(source, w.lo, w.hi, /*descending=*/false);
            },
            10.0, 100.0)
        .order_by_consumed("addr")
        // Bounded range consumed in DESCENDING addr order (ORDER BY addr DESC
        // LIMIT N stops after N derived rows instead of sorting a full scan).
        .constraint_filter(
            {xsql::optional_ge("addr"), xsql::optional_gt("addr"),
             xsql::optional_lt("addr"), xsql::optional_le("addr")},
            [source](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<model::MemoryByteRow>> {
                const auto w = memory_bytes_window_from_args(args);
                return make_memory_bytes_generator(source, w.lo, w.hi, /*descending=*/true);
            },
            10.0, 100.0)
        .order_by_consumed("addr", true)
        .build();
}

// ============================================================================
// byte_search — canonical cross-tool byte-pattern search, conforming
// to the idasql reference shape. Pure client-side: enumerates memory blocks and
// reads each through the EXISTING read_bytes RPC, matching a FlexHex pattern in
// C++ — no Java host / proto leg is added. Visible: addr, matched_hex,
// matched_bytes(BLOB), size. Hidden inputs: pattern (REQUIRED), start_addr,
// end_addr, max_results.
// ============================================================================

struct ByteSearchRow {
    std::int64_t address = 0;
    std::vector<std::uint8_t> matched_bytes;
    std::string matched_hex;
};

// One byte of a FlexHex pattern: match requires (data & mask) == (value & mask).
struct ByteSearchPatternByte {
    std::uint8_t value = 0;
    std::uint8_t mask = 0;
};

// FlexHex parse (shared vocabulary with idasql/bnsql/r2): "48 8B", "488B",
// "48 ?? 00", "4?"/"?F" nibble wildcards. false on any invalid nibble / odd count.
inline bool byte_search_parse(const std::string& pattern,
                              std::vector<ByteSearchPatternByte>& out) {
    out.clear();
    std::string s;
    for (char c : pattern)
        if (!std::isspace(static_cast<unsigned char>(c))) s += c;
    if (s.empty() || (s.size() % 2) != 0) return false;
    auto nib = [](char c, std::uint8_t& v, bool& any) -> bool {
        if (c == '?') { any = true; v = 0; return true; }
        if (c >= '0' && c <= '9') { any = false; v = std::uint8_t(c - '0'); return true; }
        if (c >= 'a' && c <= 'f') { any = false; v = std::uint8_t(10 + c - 'a'); return true; }
        if (c >= 'A' && c <= 'F') { any = false; v = std::uint8_t(10 + c - 'A'); return true; }
        return false;
    };
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        std::uint8_t hi = 0, lo = 0; bool ha = false, la = false;
        if (!nib(s[i], hi, ha) || !nib(s[i + 1], lo, la)) return false;
        ByteSearchPatternByte pb;
        pb.value = std::uint8_t((hi << 4) | lo);
        pb.mask = std::uint8_t((ha ? 0x00 : 0xF0) | (la ? 0x00 : 0x0F));
        out.push_back(pb);
    }
    return !out.empty();
}

// Space-separated lowercase 2-digit hex, matching idasql/bnsql/r2 matched_hex.
inline std::string byte_search_hex(const std::uint8_t* data, std::size_t len) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < len; ++i) {
        if (i) s += ' ';
        s += d[data[i] >> 4];
        s += d[data[i] & 0xf];
    }
    return s;
}

constexpr std::uint64_t kByteSearchPageCandidates = 32 * 1024;

// One run of candidate match starts, inclusive, in unsigned address terms.
struct ByteSearchRegion {
    std::uint64_t start = 0;
    std::uint64_t end_incl = 0;
};

// Lazy bounded-page scanner. Each page owns at most 32 Ki candidate starts and
// reads pattern_length-1 overlap bytes, so SQL LIMIT stops future RPCs and a
// multi-gigabyte block never becomes one allocation or one uint32-truncated
// ReadBytes call.
//
// `windows` are the unsigned spans of candidate START addresses to search, in
// SQL order (xsql::Int64KeyRange::unsigned_spans: the part at or above 2^63,
// whose addresses are negative INTEGERs, first), already narrowed to the
// start_addr / end_addr scan bounds. A match must fit inside one initialized
// block -- which may straddle 2^63 -- and belongs to the window its START falls
// in, so the rows come out in SQL order and the ORDER BY addr claim holds.
class ByteSearchGenerator final : public xsql::Generator<ByteSearchRow> {
public:
    ByteSearchGenerator(const std::shared_ptr<Source>& source,
                        std::vector<ByteSearchPatternByte> pat,
                        std::vector<xsql::U64Span> windows,
                        std::size_t max_results)
        : source_(source),
          pattern_(std::move(pat)),
          windows_(std::move(windows)),
          max_results_(max_results) {}

    bool next() override {
        if (!initialized_) {
            initialized_ = true;
            init();
        }
        if (empty_ ||
            (max_results_ != 0 && emitted_ >= max_results_)) {
            return false;
        }

        for (;;) {
            while (page_candidate_index_ < page_candidate_count_) {
                const std::size_t i = page_candidate_index_++;
                bool matched = true;
                for (std::size_t j = 0; j < pattern_.size(); ++j) {
                    if (std::uint8_t(page_[i + j] & pattern_[j].mask) !=
                        std::uint8_t(pattern_[j].value & pattern_[j].mask)) {
                        matched = false;
                        break;
                    }
                }
                if (!matched) {
                    continue;
                }
                current_.address = static_cast<std::int64_t>(page_start_ + i);
                current_.matched_bytes.assign(
                    page_.begin() + static_cast<std::ptrdiff_t>(i),
                    page_.begin() + static_cast<std::ptrdiff_t>(
                        i + pattern_.size()));
                current_.matched_hex = byte_search_hex(
                    current_.matched_bytes.data(),
                    current_.matched_bytes.size());
                ++emitted_;
                return true;
            }
            if (!load_next_page()) {
                return false;
            }
        }
    }

    const ByteSearchRow& current() const override { return current_; }
    std::int64_t rowid() const override { return current_.address; }

private:
    void init() {
        if (!source_ || pattern_.empty() || windows_.empty()) {
            empty_ = true;
            return;
        }

        std::vector<model::MemoryBlockRow> blocks;
        if (!source_->read_memory_blocks(blocks)) {
            empty_ = true;
            if (xsql::get_vtab_error().empty()) {
                report_write_error(
                    source_, "byte_search: failed to read memory blocks");
            }
            return;
        }

        // Candidate starts of each initialized block, in unsigned order: a
        // block's end is exclusive and modulo 2^64 (a block through
        // 0xFFFFFFFFFFFFFFFF ends at 0), and the last candidate leaves room for
        // the whole pattern inside the block.
        const std::uint64_t pattern_tail =
            static_cast<std::uint64_t>(pattern_.size()) - 1;
        std::vector<ByteSearchRegion> candidates;
        candidates.reserve(blocks.size());
        for (const auto& blk : blocks) {
            const std::uint64_t size = address_span_size(blk.start_ea, blk.end_ea);
            if (blk.is_initialized == 0 || size <= pattern_tail) {
                continue;
            }
            const auto start = static_cast<std::uint64_t>(blk.start_ea);
            candidates.push_back({start, start + (size - 1 - pattern_tail)});
        }
        std::sort(candidates.begin(), candidates.end(),
                  [](const ByteSearchRegion& lhs, const ByteSearchRegion& rhs) {
                      return lhs.start < rhs.start;
                  });
        // Overlapping blocks describe the same address bytes. Clamp later
        // candidates so a match is emitted once and rowids stay unique.
        std::vector<ByteSearchRegion> clamped;
        clamped.reserve(candidates.size());
        for (auto c : candidates) {
            if (!clamped.empty() && c.start <= clamped.back().end_incl) {
                if (clamped.back().end_incl == std::numeric_limits<std::uint64_t>::max()) {
                    continue;
                }
                c.start = clamped.back().end_incl + 1;
                if (c.end_incl < c.start) {
                    continue;
                }
            }
            clamped.push_back(c);
        }

        for (const xsql::U64Span& window : windows_) {
            for (const auto& c : clamped) {
                const std::uint64_t lo = std::max(c.start, window.lo);
                const std::uint64_t hi = std::min(c.end_incl, window.hi);
                if (lo <= hi) {
                    regions_.push_back({lo, hi});
                }
            }
        }
        empty_ = regions_.empty();
    }

    void advance_candidates(std::uint64_t count) {
        const auto& region = regions_[region_index_];
        // Candidates left after the cursor's own; a region is a block's
        // candidates, never all 2^64 addresses, so this cannot overflow.
        const std::uint64_t after_cursor = region.end_incl - cursor_;
        if (count > after_cursor) {
            ++region_index_;
            cursor_valid_ = false;
        } else {
            cursor_ += count;
        }
    }

    bool load_next_page() {
        page_.clear();
        page_candidate_index_ = 0;
        page_candidate_count_ = 0;

        while (region_index_ < regions_.size()) {
            const auto& region = regions_[region_index_];
            if (!cursor_valid_) {
                cursor_ = region.start;
                cursor_valid_ = true;
            }
            const std::uint64_t remaining = region.end_incl - cursor_ + 1;
            const std::uint64_t requested_candidates =
                std::min(remaining, kByteSearchPageCandidates);
            const std::uint64_t requested_bytes =
                requested_candidates + pattern_.size() - 1;
            page_start_ = cursor_;

            const bool read_ok = source_->read_bytes(
                static_cast<std::int64_t>(page_start_),
                static_cast<std::int64_t>(requested_bytes),
                page_);
            if (!read_ok && !xsql::get_vtab_error().empty()) {
                empty_ = true;
                return false;
            }

            std::uint64_t consumed_candidates = requested_candidates;
            if (read_ok && page_.size() >= pattern_.size()) {
                const std::uint64_t available =
                    static_cast<std::uint64_t>(
                        page_.size() - pattern_.size() + 1);
                page_candidate_count_ = static_cast<std::size_t>(
                    std::min(requested_candidates, available));
                if (page_candidate_count_ != 0) {
                    consumed_candidates = page_candidate_count_;
                }
            }
            advance_candidates(consumed_candidates);
            if (page_candidate_count_ != 0) {
                return true;
            }
        }
        return false;
    }

    std::shared_ptr<Source> source_;
    std::vector<ByteSearchPatternByte> pattern_;
    std::vector<xsql::U64Span> windows_;
    bool empty_ = false;
    bool initialized_ = false;
    std::size_t max_results_ = 0;
    std::size_t emitted_ = 0;

    std::vector<ByteSearchRegion> regions_;
    std::size_t region_index_ = 0;
    std::uint64_t cursor_ = 0;
    bool cursor_valid_ = false;

    std::vector<std::uint8_t> page_;
    std::uint64_t page_start_ = 0;
    std::size_t page_candidate_index_ = 0;
    std::size_t page_candidate_count_ = 0;
    ByteSearchRow current_{};
};

// Column indices — visible first, hidden after. Keep in sync with the def below.
enum ByteSearchColumn {
    kByteSearchAddr = 0, kByteSearchMatchedHex = 1, kByteSearchMatchedBytes = 2,
    kByteSearchSize = 3, kByteSearchPattern = 4, kByteSearchStart = 5,
    kByteSearchEnd = 6, kByteSearchMaxResults = 7,
};

inline std::unique_ptr<xsql::Generator<ByteSearchRow>> make_byte_search_generator(
    const std::shared_ptr<Source>& source,
    const std::vector<xsql::GeneratorConstraintArg>& args)
{
    // Every constraint is omit=1. The hidden inputs take a value only when a
    // native column of their type would equal it (pattern = NULL, start_addr =
    // 4096.5 and max_results = 1.5 request nothing), and every addr bound is
    // compared the way SQLite compares the INTEGER addr column.
    //
    // start_addr / end_addr are unsigned scan bounds, as in idasql and bnsql: a
    // match starts at or after start_addr and before end_addr, bit-cast from
    // SQL like every address. The addr window is searched as its unsigned spans
    // in SQL order (xsql::Int64KeyRange::unsigned_spans): an address >= 2^63 is
    // a negative INTEGER, so the part of the window at or above 2^63 comes first.
    std::string pattern;
    xsql::Int64KeyRange window;
    std::uint64_t scan_lo = 0;
    std::uint64_t scan_hi = std::numeric_limits<std::uint64_t>::max();  // inclusive
    bool scan_empty = false;
    std::size_t max_results = 0;
    for (const auto& a : args) {
        if (a.column_index == kByteSearchAddr) {
            if (a.op != xsql::ConstraintOp::Like) window.constrain(a.op, a.value);
            continue;
        }
        if (a.op != xsql::ConstraintOp::Eq) continue;
        if (a.column_index == kByteSearchPattern) {
            std::optional<std::string> text = xsql::exact_text(a.value);
            if (!text) return nullptr;
            pattern = std::move(*text);
            continue;
        }
        if (a.column_index != kByteSearchStart && a.column_index != kByteSearchEnd &&
            a.column_index != kByteSearchMaxResults) {
            continue;
        }
        const std::optional<std::int64_t> value = xsql::exact_int64(a.value);
        if (!value) return nullptr;
        if (a.column_index == kByteSearchStart) {
            scan_lo = std::max(scan_lo, static_cast<std::uint64_t>(*value));
        } else if (a.column_index == kByteSearchEnd) {
            const auto end = static_cast<std::uint64_t>(*value);  // exclusive
            if (end == 0) {
                scan_empty = true;
            } else {
                scan_hi = std::min(scan_hi, end - 1);
            }
        } else if (*value > 0) {
            max_results = static_cast<std::size_t>(*value);
        }
    }
    std::vector<xsql::U64Span> windows;
    if (!scan_empty && scan_lo <= scan_hi) {
        for (const xsql::U64Span& span : window.unsigned_spans()) {
            const std::uint64_t lo = std::max(span.lo, scan_lo);
            const std::uint64_t hi = std::min(span.hi, scan_hi);
            if (lo <= hi) windows.push_back({lo, hi});
        }
    }
    std::vector<ByteSearchPatternByte> parsed;
    byte_search_parse(pattern, parsed);    // empty/invalid -> no matches
    const std::uint64_t max_pattern =
        std::numeric_limits<std::uint32_t>::max() -
        kByteSearchPageCandidates + 1;
    if (parsed.size() > max_pattern) {
        xsql::set_vtab_error(
            "byte_search pattern is too large for the ReadBytes protocol");
        parsed.clear();
    }
    return std::make_unique<ByteSearchGenerator>(
        source, std::move(parsed), std::move(windows), max_results);
}

inline xsql::GeneratorTableDef<ByteSearchRow> define_byte_search(const std::shared_ptr<Source>& source) {
    return xsql::generator_table<ByteSearchRow>("byte_search")
        .estimate_rows([]() -> std::size_t { return 64; })
        .column_int64("addr", [](const ByteSearchRow& r) { return r.address; })
        .column_text("matched_hex", [](const ByteSearchRow& r) { return r.matched_hex; })
        .column_blob("matched_bytes",
                     [](const ByteSearchRow& r) { return r.matched_bytes; })
        .column_int("size",
                    [](const ByteSearchRow& r) { return static_cast<int>(r.matched_bytes.size()); })
        .hidden_column_text("pattern")
        .hidden_column_int64("start_addr")
        .hidden_column_int64("end_addr")
        .hidden_column_int("max_results")
        .full_scan_error(
            "byte_search requires WHERE pattern = '<FlexHex byte pattern>'; "
            "matched_hex is an output column, not the search input")
        .constraint_filter(
            {xsql::required_eq("pattern",
                 "byte_search requires WHERE pattern = '<FlexHex byte pattern>'"),
             xsql::optional_eq("start_addr"),
             xsql::optional_eq("end_addr"),
             xsql::optional_eq("max_results"),
             xsql::optional_ge("addr"), xsql::optional_gt("addr"),
             xsql::optional_lt("addr"), xsql::optional_le("addr")},
            [source](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<ByteSearchRow>> {
                return make_byte_search_generator(source, args);
            },
            1.0, 64.0)
        .order_by_consumed("addr")
        .build();
}

// An external symbol's addr is an offset in Ghidra's EXTERNAL space, not a
// memory address, while the symbol writes name a memory address: on an image
// mapped at low addresses (firmware at 0) that offset is another symbol's
// address. Refuse rather than write that symbol.
inline bool names_row_is_addressable(const model::SymbolRow& row, const char* verb) {
    if (row.is_external == 0) {
        return true;
    }
    xsql::set_vtab_error(std::string(verb) + " names: '" + row.name +
        "' is an external symbol; its addr is an EXTERNAL-space offset, not a memory address");
    return false;
}

inline xsql::CachedTableDef<KeyedRow<model::SymbolRow>> define_names(
    const std::shared_ptr<Source>& source,
    const std::shared_ptr<QueryScopeState>& query_scope) {
    return xsql::cached_table<KeyedRow<model::SymbolRow>>("names")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::SymbolRow> rows;
            return source->read_symbols(rows) ? rows.size() : size_t(0);
        })
        .cache_builder([source, query_scope](std::vector<KeyedRow<model::SymbolRow>>& out) {
            std::vector<model::SymbolRow> rows;
            if (!source->read_symbols(rows)) {
                rows.clear();
            }
            auto indexed = key_by_address_slot(std::move(rows), address_row_ids());
            out = keyed_rows_of(indexed);
            query_scope->name_rows.store(std::move(indexed));
        })
        // (address, index at that address) -- the addr filter's key.
        .rowid([](const KeyedRow<model::SymbolRow>& r) { return r.row_key; })
        .column_int64("addr", [](const model::SymbolRow& r) { return r.address; })
        .column_text_rw(
            "name",
            [](const model::SymbolRow& r) { return r.name; },
            [source](model::SymbolRow& row, const char* name) {
                // The row's own name picks the symbol, so a secondary label is
                // renamed exactly, never the primary symbol at its address.
                if (!names_row_is_addressable(row, "UPDATE")) {
                    return false;
                }
                if (!source->rename_symbol(row.address, row.name, name ? name : "")) {
                    report_write_error(source, "UPDATE names.name failed: rename_symbol '" +
                        row.name + "' at " + addr_hex(row.address));
                    return false;
                }
                return true;
            })
        .column_text("symbol_kind", [](const model::SymbolRow& r) { return r.symbol_kind; })
        .column_text("namespace", [](const model::SymbolRow& r) { return r.namespace_name; })
        .column_int("is_primary", [](const model::SymbolRow& r) { return r.is_primary; })
        .column_int("is_external", [](const model::SymbolRow& r) { return r.is_external; })
        .deletable([source](model::SymbolRow& row) {
            if (!names_row_is_addressable(row, "DELETE FROM")) {
                return false;
            }
            return source->delete_symbol(row.address, row.name);
        })
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
                xsql::set_vtab_error("INSERT INTO names requires addr and name");
                return false;
            }
            const std::int64_t address = argv[0].as_int64();
            const char* name = argv[1].as_c_str();
            if (!name || !name[0]) {
                xsql::set_vtab_error("INSERT INTO names: name must not be empty");
                return false;
            }
            if (!source->create_symbol(address, name)) {
                report_write_error(source, "INSERT INTO names failed: create_symbol at " +
                    addr_hex(address));
                return false;
            }
            return true;
        })
        .row_lookup([source, query_scope](model::SymbolRow& row, std::int64_t raw_rowid) {
            if (query_scope->name_rows.lookup(raw_rowid, row)) {
                return true;
            }
            std::int64_t address = 0;
            size_t slot = 0;
            if (!address_row_ids().decode(raw_rowid, address, slot)) {
                return false;
            }
            std::vector<model::SymbolRow> rows;
            if (!source->read_symbols_at(address, rows) || slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .filter_eq("addr",
            [source, query_scope](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::SymbolRow> rows;
                source->read_symbols_at(address, rows);
                std::vector<std::pair<std::int64_t, model::SymbolRow>> indexed;
                indexed.reserve(rows.size());
                for (size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(address_row_ids().encode(address, i), std::move(rows[i]));
                }
                query_scope->name_rows.store(indexed);
                return std::make_unique<IndexedOwnedRowIterator<model::SymbolRow>>(
                    std::move(indexed),
                    column_symbol);
            }, 1.0, 4.0)
        .index_on("addr", [](const model::SymbolRow& r) { return r.address; })
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
        .column_int64("addr", [](const model::ImportRow& r) { return r.address; })
        .column_text("name", [](const model::ImportRow& r) { return r.name; })
        .column_text("module", [](const model::ImportRow& r) { return r.module; })
        .filter_eq_text(
            "module",
            [source](const std::string& module) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::ImportRow> all_rows;
                std::vector<model::ImportRow> rows;
                if (source->read_imports(all_rows)) {
                    const std::string needle = module;
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
        .index_on("addr", [](const model::ImportRow& r) { return r.address; })
        .build();
}

inline xsql::CachedTableDef<model::ExportRow> define_exports(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::ExportRow>("entries")
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
        .column_int64("addr", [](const model::ExportRow& r) { return r.address; })
        .column_text("name", [](const model::ExportRow& r) { return r.name; })
        .column_text("module", [](const model::ExportRow& r) { return r.module; })
        .filter_eq_text(
            "module",
            [source](const std::string& module) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::ExportRow> all_rows;
                std::vector<model::ExportRow> rows;
                if (source->read_exports(all_rows)) {
                    const std::string needle = module;
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
        .index_on("addr", [](const model::ExportRow& r) { return r.address; })
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
        .column_int64("addr", [](const model::StringRow& r) { return r.address; })
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
            [source](const std::string& content) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::StringRow> all_rows;
                std::vector<model::StringRow> rows;
                if (source->read_strings(all_rows)) {
                    const std::string needle = content;
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
        .filter_eq("addr",
            [source](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::StringRow> rows;
                source->read_strings_at(address, rows);
                return std::make_unique<OwnedRowIterator<model::StringRow>>(
                    std::move(rows),
                    column_string);
            }, 1.0, 2.0)
        .index_on("addr", [](const model::StringRow& r) { return r.address; })
        .build();
}

inline std::vector<model::StringRefRow> make_string_ref_rows(
        const std::vector<model::XrefRow>& refs,
        const std::vector<model::StringRow>& strings,
        std::int64_t function_address,
        const std::string& function_name) {
    std::unordered_map<std::int64_t, const model::StringRow*> strings_by_addr;
    strings_by_addr.reserve(strings.size());
    for (const auto& value : strings) {
        strings_by_addr.emplace(value.address, &value);
    }

    std::vector<model::StringRefRow> rows;
    rows.reserve(refs.size());
    for (const auto& ref : refs) {
        if (xsql::vtab_interrupted()) {
            break;
        }
        const auto found = strings_by_addr.find(ref.to_ea);
        if (found == strings_by_addr.end()) {
            continue;
        }
        const auto& value = *found->second;
        model::StringRefRow row;
        row.string_addr = value.address;
        row.string_value = value.content;
        row.string_length = value.length;
        row.ref_addr = ref.from_ea;
        row.func_addr = function_address;
        row.func_name = function_name;
        rows.push_back(std::move(row));
    }
    return rows;
}

inline xsql::CachedTableDef<model::StringRefRow> define_string_refs(
        const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::StringRefRow>("string_refs")
        .no_shared_cache()
        // A full scan remains available for whole-program reports, but exact
        // function lookups below avoid materializing unrelated function rows.
        .estimate_rows([]() { return size_t(10000); })
        .cache_builder([source](std::vector<model::StringRefRow>& out) {
            std::vector<model::XrefRow> refs;
            std::vector<model::StringRow> strings;
            std::vector<model::FunctionRow> functions;
            if (!source->read_xrefs(refs) || xsql::vtab_interrupted() ||
                !source->read_strings(strings) || xsql::vtab_interrupted() ||
                !source->read_functions(functions)) {
                out.clear();
                return;
            }
            const auto ranges = build_function_ranges(functions);
            std::unordered_map<std::int64_t, std::string> names_by_addr;
            names_by_addr.reserve(functions.size());
            for (const auto& function : functions) {
                names_by_addr.emplace(function.address, function.name);
            }
            std::unordered_map<std::int64_t, const model::StringRow*> strings_by_addr;
            strings_by_addr.reserve(strings.size());
            for (const auto& value : strings) {
                strings_by_addr.emplace(value.address, &value);
            }
            out.reserve(refs.size());
            for (const auto& ref : refs) {
                if (xsql::vtab_interrupted()) {
                    out.clear();
                    return;
                }
                const auto string_it = strings_by_addr.find(ref.to_ea);
                if (string_it == strings_by_addr.end()) {
                    continue;
                }
                const auto function_address = function_for_address(ranges, ref.from_ea);
                const auto name_it = names_by_addr.find(function_address);
                const auto& value = *string_it->second;
                model::StringRefRow row;
                row.string_addr = value.address;
                row.string_value = value.content;
                row.string_length = value.length;
                row.ref_addr = ref.from_ea;
                row.func_addr = function_address;
                row.func_name = name_it != names_by_addr.end() ? name_it->second : "";
                out.push_back(std::move(row));
            }
        })
        .column_int64("string_addr", [](const model::StringRefRow& r) { return r.string_addr; })
        .column_text("string_value", [](const model::StringRefRow& r) { return r.string_value; })
        .column_int64("string_length", [](const model::StringRefRow& r) { return r.string_length; })
        .column_int64("ref_addr", [](const model::StringRefRow& r) { return r.ref_addr; })
        .column_int64("func_addr", [](const model::StringRefRow& r) { return r.func_addr; })
        .column_text("func_name", [](const model::StringRefRow& r) { return r.func_name; })
        .filter_eq("func_addr",
            [source](std::int64_t function_address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::XrefRow> refs;
                std::vector<model::StringRow> strings;
                std::vector<model::StringRefRow> rows;
                if (source->read_xrefs_from_function(function_address, refs) &&
                    !xsql::vtab_interrupted() && source->read_strings(strings) &&
                    !xsql::vtab_interrupted()) {
                    model::FunctionRow function;
                    std::string function_name;
                    if (source->read_function_at(function_address, function)) {
                        function_name = function.name;
                    }
                    rows = make_string_ref_rows(
                        refs, strings, function_address, function_name);
                }
                return std::make_unique<OwnedRowIterator<model::StringRefRow>>(
                    std::move(rows), column_string_ref);
            },
            5.0,
            64.0)
        .index_on("string_addr", [](const model::StringRefRow& r) { return r.string_addr; })
        .index_on("ref_addr", [](const model::StringRefRow& r) { return r.ref_addr; })
        .index_on("func_addr", [](const model::StringRefRow& r) { return r.func_addr; })
        .build();
}

inline xsql::CachedTableDef<model::XrefRow> define_xrefs(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::XrefRow>("xrefs")
        .no_shared_cache()
        // Never materialize all references merely to estimate the table; the
        // cache builder below is already the required expensive operation.
        .estimate_rows([]() { return size_t(100000); })
        .cache_builder([source](std::vector<model::XrefRow>& out) {
            if (!source->read_xrefs(out)) {
                out.clear();
            }
        })
        .column_int64("from_addr", [](const model::XrefRow& r) { return r.from_ea; })
        .column_int64("to_addr", [](const model::XrefRow& r) { return r.to_ea; })
        .column_text("kind", [](const model::XrefRow& r) { return r.kind; })
        .column_int("is_code", [](const model::XrefRow& r) { return r.is_code; })
        .column_int("is_data", [](const model::XrefRow& r) { return r.is_data; })
        .filter_eq("from_addr",
            [source](std::int64_t from_addr) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::XrefRow> rows;
                source->read_xrefs_from(from_addr, rows);
                return std::make_unique<OwnedRowIterator<model::XrefRow>>(
                    std::move(rows), column_xref);
            },
            2.0,
            8.0)
        .filter_eq("to_addr",
            [source](std::int64_t to_addr) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::XrefRow> rows;
                source->read_xrefs_to(to_addr, rows);
                return std::make_unique<OwnedRowIterator<model::XrefRow>>(
                    std::move(rows), column_xref);
            },
            2.0,
            8.0)
        .filter_eq_text(
            "kind",
            [source](const std::string& kind) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::XrefRow> all_rows;
                std::vector<model::XrefRow> rows;
                if (source->read_xrefs(all_rows)) {
                    const std::string needle = kind;
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
        .index_on("from_addr", [](const model::XrefRow& r) { return r.from_ea; })
        .index_on("to_addr", [](const model::XrefRow& r) { return r.to_ea; })
        .build();
}

inline xsql::CachedTableDef<model::CallEdgeRow> define_call_edges(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::CallEdgeRow>("call_edges")
        .no_shared_cache()
        // Cardinality discovery must not perform the same whole-program xref
        // traversal that execution may require. A stable conservative estimate
        // lets exact src_func_addr predicates reach the bounded reader below.
        .estimate_rows([]() { return size_t(100000); })
        .cache_builder([source](std::vector<model::CallEdgeRow>& out) {
            out = derive_call_edge_rows(source);
        })
        .column_int64("src_func_addr", [](const model::CallEdgeRow& r) { return r.src_func_addr; })
        .column_text("src_func_name", [](const model::CallEdgeRow& r) { return r.src_func_name; })
        .column_int64("call_site", [](const model::CallEdgeRow& r) { return r.call_site; })
        .column_int64("dst_addr", [](const model::CallEdgeRow& r) { return r.dst_addr; })
        .column_int64("dst_func_addr", [](const model::CallEdgeRow& r) { return r.dst_func_addr; })
        .column_text("dst_func_name", [](const model::CallEdgeRow& r) { return r.dst_func_name; })
        .column_text("kind", [](const model::CallEdgeRow& r) { return r.kind; })
        .filter_eq("src_func_addr",
            [source](std::int64_t function_address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::CallEdgeRow> rows;
                source->read_call_edges_from(function_address, rows);
                return std::make_unique<OwnedRowIterator<model::CallEdgeRow>>(
                    std::move(rows), column_call_edge);
            },
            8.0,
            64.0)
        .filter_eq("dst_func_addr",
            [source](std::int64_t function_address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::CallEdgeRow> rows;
                source->read_call_edges_to(function_address, rows);
                return std::make_unique<OwnedRowIterator<model::CallEdgeRow>>(
                    std::move(rows), column_call_edge);
            },
            8.0,
            64.0)
        // Raw destination. dst_func_addr only identifies edges whose target is
        // a function entry; imports, PLT/thunk stubs and unresolved indirect
        // targets have dst_func_addr == 0 and are identified solely by
        // dst_addr. Without this filter the `callers` view's unresolved union
        // arm plans as VIRTUAL TABLE INDEX 0 and falls through to the
        // whole-program cache builder, so an exact `callers WHERE func_addr = X`
        // paid a global ListFunctions on top of the bounded lookup.
        .filter_eq("dst_addr",
            [source](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::CallEdgeRow> rows;
                source->read_call_edges_to_addr(address, rows);
                return std::make_unique<OwnedRowIterator<model::CallEdgeRow>>(
                    std::move(rows), column_call_edge);
            },
            8.0,
            64.0)
        .filter_eq("call_site",
            [source](std::int64_t call_site) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::CallEdgeRow> rows;
                source->read_call_edges_at(call_site, rows);
                return std::make_unique<OwnedRowIterator<model::CallEdgeRow>>(
                    std::move(rows), column_call_edge);
            },
            3.0,
            2.0)
        .index_on("src_func_addr", [](const model::CallEdgeRow& r) { return r.src_func_addr; })
        .index_on("dst_func_addr", [](const model::CallEdgeRow& r) { return r.dst_func_addr; })
        .index_on("dst_addr", [](const model::CallEdgeRow& r) { return r.dst_addr; })
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
        .column_int64("start_addr", [](const model::BlockRow& r) { return r.start_ea; })
        .column_int64("end_addr", [](const model::BlockRow& r) { return r.end_ea; })
        .column_int64("size", [](const model::BlockRow& r) {
            return static_cast<std::int64_t>(address_span_size(r.start_ea, r.end_ea));
        })
        .column_int("in_degree", [](const model::BlockRow& r) { return r.in_degree; })
        .column_int("out_degree", [](const model::BlockRow& r) { return r.out_degree; })
        .index_on("func_addr", [](const model::BlockRow& r) { return r.func_addr; })
        .index_on("start_addr", [](const model::BlockRow& r) { return r.start_ea; })
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
        // Canonical cross-tool cfg_edges columns (was src_start_addr/dst_start_addr/
        // edge_kind); the ratified from_addr/to_addr edge token. Model fields keep
        // their libghidra names (src_start_ea/dst_start_ea/edge_kind).
        .column_int64("func_addr", [](const model::CfgEdgeRow& r) { return r.func_addr; })
        .column_int64("from_addr", [](const model::CfgEdgeRow& r) { return r.src_start_ea; })
        .column_int64("to_addr", [](const model::CfgEdgeRow& r) { return r.dst_start_ea; })
        .column_text("edge_type", [](const model::CfgEdgeRow& r) { return r.edge_kind; })
        .index_on("func_addr", [](const model::CfgEdgeRow& r) { return r.func_addr; })
        .index_on("from_addr", [](const model::CfgEdgeRow& r) { return r.src_start_ea; })
        .index_on("to_addr", [](const model::CfgEdgeRow& r) { return r.dst_start_ea; })
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
        .column_int64("header_addr", [](const model::LoopRow& r) { return r.header_ea; })
        .column_int64("latch_addr", [](const model::LoopRow& r) { return r.latch_ea; })
        .column_int64("start_addr", [](const model::LoopRow& r) { return r.start_ea; })
        .column_int64("end_addr", [](const model::LoopRow& r) { return r.end_ea; })
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
        .column_int64("instr_addr", [](const model::SwitchTableRow& r) { return r.instr_ea; })
        .column_int64("table_addr", [](const model::SwitchTableRow& r) { return r.table_ea; })
        .column_int64("min_case", [](const model::SwitchTableRow& r) { return r.min_case; })
        .column_int64("max_case", [](const model::SwitchTableRow& r) { return r.max_case; })
        .column_int64("case_count", [](const model::SwitchTableRow& r) { return r.case_count; })
        .column_int64("default_addr", [](const model::SwitchTableRow& r) { return r.default_ea; })
        .index_on("func_addr", [](const model::SwitchTableRow& r) { return r.func_addr; })
        .index_on("instr_addr", [](const model::SwitchTableRow& r) { return r.instr_ea; })
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
        .column_int64("node_addr", [](const model::DominatorRow& r) { return r.node_ea; })
        // libghidra faithfully reports Ghidra's root convention (the entry
        // immediately dominates itself). The canonical cross-tool SQL contract
        // represents a missing parent as NULL, so normalize only at this adapter.
        .column("idom_addr", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const model::DominatorRow& r) {
                if (r.is_entry != 0) {
                    ctx.result_null();
                } else {
                    ctx.result_int64(r.idom_ea);
                }
            })
        .column_int("depth", [](const model::DominatorRow& r) { return r.depth; })
        .column_int("is_entry", [](const model::DominatorRow& r) { return r.is_entry; })
        .index_on("func_addr", [](const model::DominatorRow& r) { return r.func_addr; })
        .index_on("node_addr", [](const model::DominatorRow& r) { return r.node_ea; })
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
        .column_int64("node_addr", [](const model::PostDominatorRow& r) { return r.node_ea; })
        .column("ipdom_addr", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const model::PostDominatorRow& r) {
                if (r.is_exit != 0) {
                    ctx.result_null();
                } else {
                    ctx.result_int64(r.ipdom_ea);
                }
            })
        .column_int("depth", [](const model::PostDominatorRow& r) { return r.depth; })
        .column_int("is_exit", [](const model::PostDominatorRow& r) { return r.is_exit; })
        .index_on("func_addr", [](const model::PostDominatorRow& r) { return r.func_addr; })
        .index_on("node_addr", [](const model::PostDominatorRow& r) { return r.node_ea; })
        .build();
}

// Shared implementation of "read all instructions, then range-map each to its
// containing function". The cache builder and the bulk mnemonic/func_addr
// filters all call this helper, keeping the single-address and bulk paths
// consistent without duplicating attribution logic. It is strictly
// query-scoped: the caller owns `out`, and it is freed when the query ends. The
// func_addr pushdown filters are retained; this change removes the duplication,
// not the pushdown.
inline bool build_instructions_with_func_addr(const std::shared_ptr<Source>& source,
                                               std::vector<model::InstructionRow>& out) {
    if (!source->read_instructions(out)) {
        out.clear();
        return false;
    }
    std::vector<model::FunctionRow> functions;
    if (!source->read_functions(functions)) {
        out.clear();
        report_write_error(
            source, "instructions: failed to read functions for func_addr");
        return false;
    }
    assign_instruction_func_addrs(functions, out);
    return true;
}

inline bool build_instructions_for_func(
        const std::shared_ptr<Source>& source,
        std::int64_t func_addr,
        std::vector<model::InstructionRow>& out) {
    out.clear();
    model::FunctionRow function;
    if (!source->read_function_at(func_addr, function)) {
        return xsql::get_vtab_error().empty();
    }
    if (!read_function_body_runs(function, out,
            [&](std::int64_t first, std::int64_t last, std::vector<model::InstructionRow>& part) {
                return source->read_instructions_in_range(first, last, part);
            })) {
        return false;
    }
    std::vector<model::FunctionRow> functions;
    if (!source->read_functions(functions)) {
        out.clear();
        return false;
    }
    assign_instruction_func_addrs(functions, out);
    out.erase(
        std::remove_if(
            out.begin(), out.end(),
            [func_addr](const model::InstructionRow& row) {
                return row.func_addr != func_addr;
            }),
        out.end());
    return true;
}

class InstructionGenerator final : public xsql::Generator<model::InstructionRow> {
    std::vector<model::InstructionRow> rows_;
    size_t index_ = 0;
    model::InstructionRow current_;

public:
    InstructionGenerator(
        const std::shared_ptr<Source>& source,
        const std::optional<MemoryBytesWindow>& window)
    {
        bool ok = false;
        if (window) {
            ok = !window->empty && source->read_instructions_in_range(
                window->lo, window->hi, rows_);
        } else {
            ok = source->read_instructions(rows_);
        }
        if (!ok && (!window || !window->empty)) {
            rows_.clear();
            report_write_error(source, "instructions: source read failed");
            return;
        }

        std::vector<model::FunctionRow> functions;
        if (!source->read_functions(functions)) {
            rows_.clear();
            report_write_error(
                source, "instructions: failed to read functions for func_addr");
            return;
        }
        assign_instruction_func_addrs(functions, rows_);

        // The source window may include an instruction that overlaps the lower
        // boundary. SQL constrains instruction START addresses, so remove any
        // overlap-only row before claiming that the pushed predicate is exact.
        if (window) {
            rows_.erase(
                std::remove_if(rows_.begin(), rows_.end(), [&](const auto& row) {
                    return row.address < window->lo || row.address > window->hi;
                }),
                rows_.end());
        }
    }

    bool next() override {
        if (index_ >= rows_.size()) return false;
        current_ = std::move(rows_[index_++]);
        return true;
    }

    const model::InstructionRow& current() const override { return current_; }
    std::int64_t rowid() const override { return current_.address; }
};

inline xsql::GeneratorTableDef<model::InstructionRow> define_instructions(
        const std::shared_ptr<Source>& source) {
    return xsql::generator_table<model::InstructionRow>("instructions")
        // Planning must never enumerate a live program. Execution chooses the
        // source-pushed addr/func_addr paths below when constrained.
        .estimate_rows([]() { return size_t(1000000); })
        .generator([source]() {
            return std::make_unique<InstructionGenerator>(source, std::nullopt);
        })
        .column_int64("addr", [](const model::InstructionRow& r) { return r.address; })
        .column_text("mnemonic", [](const model::InstructionRow& r) { return r.mnemonic; })
        .column_text("operands", [](const model::InstructionRow& r) { return r.operands; })
        .column_text("disasm", [](const model::InstructionRow& r) { return r.disasm; })
        .column_int("size", [](const model::InstructionRow& r) { return r.size; })
        .column_text("bytes", [](const model::InstructionRow& r) { return r.bytes; })
        .column_int64("func_addr", [](const model::InstructionRow& r) { return r.func_addr; })
        .filter_eq_text(
            "mnemonic",
            [source](const std::string& mnemonic) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::InstructionRow> rows;
                std::vector<model::InstructionRow> matched;
                if (build_instructions_with_func_addr(source, rows)) {
                    const std::string needle = mnemonic;
                    matched.reserve(rows.size() / 8 + 1);
                    for (auto& row : rows) {
                        if (row.mnemonic == needle) {
                            matched.push_back(std::move(row));
                        }
                    }
                }
                return std::make_unique<OwnedRowIterator<model::InstructionRow>>(
                    std::move(matched), column_instruction);
            },
            // It reads every instruction before filtering, so it is priced
            // above every bounded read (addr point/range, func_addr) and below
            // the full scan: next to one of those, the bounded read drives the
            // scan and SQLite applies the mnemonic to its rows.
            100000.0,
            64.0)
        .filter_eq("addr",
            [source](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                model::InstructionRow row;
                std::vector<model::InstructionRow> rows;
                if (source->read_instruction_at(address, row)) {
                    std::vector<model::FunctionRow> functions;
                    if (source->read_functions(functions)) {
                        row.func_addr =
                            containing_func_addr(functions, row.address);
                        rows.push_back(std::move(row));
                    } else {
                        report_write_error(
                            source,
                            "instructions: failed to read functions for "
                            "func_addr");
                    }
                }
                return std::make_unique<OwnedRowIterator<model::InstructionRow>>(
                    std::move(rows),
                    column_instruction);
            }, 1.0, 1.0)
        .filter_eq("func_addr",
            [source](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::InstructionRow> rows;
                if (!build_instructions_for_func(source, func_addr, rows) &&
                    xsql::get_vtab_error().empty()) {
                    report_write_error(
                        source, "instructions: failed to read function window");
                }
                return std::make_unique<OwnedRowIterator<model::InstructionRow>>(
                    std::move(rows),
                    column_instruction);
            }, 10.0, 64.0)
        .constraint_filter(
            {xsql::optional_ge("addr"), xsql::optional_gt("addr"),
             xsql::optional_lt("addr"), xsql::optional_le("addr")},
            [source](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<model::InstructionRow>> {
                return std::make_unique<InstructionGenerator>(
                    source, memory_bytes_window_from_args(args));
            },
            10.0, 100.0)
        .build();
}

// Bulk operand read + canonical func_addr assignment (range-map in C++, same as
// instructions). Query-scoped: the caller owns `out`.
inline bool build_instruction_operands_with_func_addr(
        const std::shared_ptr<Source>& source,
        std::vector<model::InstructionOperandRow>& out) {
    if (!source->read_instruction_operands(out)) {
        out.clear();
        return false;
    }
    std::vector<model::FunctionRow> functions;
    if (!source->read_functions(functions)) {
        out.clear();
        report_write_error(
            source,
            "instruction_operands: failed to read functions for func_addr");
        return false;
    }
    assign_operand_func_addrs(functions, out);
    return true;
}

inline bool build_instruction_operands_for_func(
        const std::shared_ptr<Source>& source,
        std::int64_t func_addr,
        std::vector<model::InstructionOperandRow>& out) {
    out.clear();
    model::FunctionRow function;
    if (!source->read_function_at(func_addr, function)) {
        return xsql::get_vtab_error().empty();
    }
    if (!read_function_body_runs(function, out,
            [&](std::int64_t first, std::int64_t last,
                std::vector<model::InstructionOperandRow>& part) {
                return source->read_instruction_operands_in_range(first, last, part);
            })) {
        return false;
    }
    std::vector<model::FunctionRow> functions;
    if (!source->read_functions(functions)) {
        out.clear();
        return false;
    }
    assign_operand_func_addrs(functions, out);
    out.erase(
        std::remove_if(
            out.begin(), out.end(),
            [func_addr](const model::InstructionOperandRow& row) {
                return row.func_addr != func_addr;
            }),
        out.end());
    return true;
}

inline xsql::CachedTableDef<model::InstructionOperandRow> define_instruction_operands(
        const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::InstructionOperandRow>("instruction_operands")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::InstructionOperandRow> rows;
            if (source->read_instruction_operands(rows)) {
                return rows.size();
            }
            return size_t(0);
        })
        .cache_builder([source](std::vector<model::InstructionOperandRow>& out) {
            build_instruction_operands_with_func_addr(source, out);
        })
        .column_int64("addr", [](const model::InstructionOperandRow& r) { return r.address; })
        .column_int64("func_addr", [](const model::InstructionOperandRow& r) { return r.func_addr; })
        .column_int("operand_index", [](const model::InstructionOperandRow& r) { return r.operand_index; })
        .column_text("text", [](const model::InstructionOperandRow& r) { return r.text; })
        .column_text("type_name", [](const model::InstructionOperandRow& r) { return r.type_name; })
        .column_text("ref_type", [](const model::InstructionOperandRow& r) { return r.ref_type; })
        // addr pushdown: one instruction's operands via the windowed source read.
        .filter_eq("addr",
            [source](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::InstructionOperandRow> rows;
                if (source->read_instruction_operands_in_range(address, address, rows)) {
                    std::vector<model::FunctionRow> functions;
                    if (source->read_functions(functions)) {
                        assign_operand_func_addrs(functions, rows);
                    } else {
                        rows.clear();
                        report_write_error(
                            source,
                            "instruction_operands: failed to read functions "
                            "for func_addr");
                    }
                }
                return std::make_unique<OwnedRowIterator<model::InstructionOperandRow>>(
                    std::move(rows), column_instruction_operand);
            }, 1.0, 2.0)
        // func_addr pushdown: read only the function's bounded body window,
        // then retain range-mapped rows for discontiguous/overlapping bodies.
        .filter_eq("func_addr",
            [source](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::InstructionOperandRow> rows;
                if (!build_instruction_operands_for_func(
                        source, func_addr, rows) &&
                    xsql::get_vtab_error().empty()) {
                    report_write_error(
                        source,
                        "instruction_operands: failed to read function window");
                }
                return std::make_unique<OwnedRowIterator<model::InstructionOperandRow>>(
                    std::move(rows), column_instruction_operand);
            }, 10.0, 64.0)
        .index_on("addr", [](const model::InstructionOperandRow& r) { return r.address; })
        .index_on("func_addr", [](const model::InstructionOperandRow& r) { return r.func_addr; })
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

inline xsql::CachedTableDef<KeyedRow<model::CommentRow>> define_comments(
    const std::shared_ptr<Source>& source,
    const std::shared_ptr<QueryScopeState>& query_scope) {
    return xsql::cached_table<KeyedRow<model::CommentRow>>("comments")
        .no_shared_cache()
        // A live comment scan walks Ghidra's listing. Doing that during query
        // planning duplicated the cache-builder scan and made unbounded reads
        // look hung on large programs. A stable heuristic is sufficient here.
        .estimate_rows([]() { return size_t(10000); })
        .cache_builder([source, query_scope](std::vector<KeyedRow<model::CommentRow>>& out) {
            std::vector<model::CommentRow> rows;
            if (!source->read_comments(rows)) {
                rows.clear();
            }
            auto indexed = key_by_address_slot(std::move(rows), comment_row_ids());
            out = keyed_rows_of(indexed);
            query_scope->comment_rows.store(std::move(indexed));
        })
        // (address, index at that address) -- the addr filter's key.
        .rowid([](const KeyedRow<model::CommentRow>& r) { return r.row_key; })
        .column_int64("addr", [](const model::CommentRow& r) { return r.address; })
        .column_text_rw(
            "comment",
            [](const model::CommentRow& r) { return r.comment; },
            [source](model::CommentRow& row, const char* text) {
                const std::string next = text ? text : "";
                if (row.comment == next) {
                    return true;
                }
                if (!first_comment_write_that_succeeds(
                        "UPDATE comments.comment failed at " + addr_hex(row.address),
                        {[&] {
                             return !row.source.empty() &&
                                 source->set_comment_by_kind(row.address, next, row.source);
                         },
                         [&] {
                             return comment_kind_has_flag_form(row.source) &&
                                 source->set_comment(row.address, next, row.repeatable != 0);
                         }})) {
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
                        "UPDATE comments.repeatable failed at " + addr_hex(row.address));
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
                        "UPDATE comments.source failed at " + addr_hex(row.address));
                    return false;
                }
                // Moving the comment means removing it from its previous kind;
                // if that fails the comment now sits under both kinds.
                if (!row.source.empty() &&
                    !source->delete_comment_by_kind(row.address, row.source)) {
                    report_write_error(
                        source,
                        "UPDATE comments.source at " + addr_hex(row.address) +
                            ": the comment was written as '" + next +
                            "' but the '" + row.source + "' comment was not removed");
                    return false;
                }
                row.source = next;
                row.repeatable = (next == "repeatable") ? 1 : 0;
                return true;
            })
        .deletable([source](model::CommentRow& row) {
            return first_comment_write_that_succeeds(
                "DELETE FROM comments failed at " + addr_hex(row.address),
                {[&] { return source->delete_comment_by_kind(row.address, row.source); },
                 [&] {
                     return comment_kind_has_flag_form(row.source) &&
                         source->delete_comment(row.address, row.repeatable != 0);
                 }});
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
        .row_lookup([source, query_scope](model::CommentRow& row, std::int64_t raw_rowid) {
            if (query_scope->comment_rows.lookup(raw_rowid, row)) {
                return true;
            }
            std::int64_t address = 0;
            size_t slot = 0;
            if (!comment_row_ids().decode(raw_rowid, address, slot)) {
                return false;
            }
            std::vector<model::CommentRow> rows;
            if (!source->read_comments_at(address, rows) || slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .filter_eq("addr",
            [source, query_scope](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::CommentRow> rows;
                source->read_comments_at(address, rows);
                std::vector<std::pair<std::int64_t, model::CommentRow>> indexed;
                indexed.reserve(rows.size());
                for (size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(comment_row_ids().encode(address, i), std::move(rows[i]));
                }
                query_scope->comment_rows.store(indexed);
                return std::make_unique<IndexedOwnedRowIterator<model::CommentRow>>(
                    std::move(indexed),
                    column_comment);
            }, 1.0, 1.0)
        .build();
}

class DataItemGenerator final : public xsql::Generator<model::DataItemRow> {
    std::vector<std::pair<std::int64_t, model::DataItemRow>> rows_;
    size_t index_ = 0;
    model::DataItemRow current_;
    std::int64_t current_rowid_ = 0;

public:
    DataItemGenerator(
        const std::shared_ptr<Source>& source,
        const std::optional<MemoryBytesWindow>& window)
    {
        std::vector<model::DataItemRow> rows;
        bool ok = false;
        if (window) {
            ok = source->read_data_items_in_range(window->lo, window->hi, rows);
        } else {
            ok = source->read_data_items(rows);
        }
        if (!ok) {
            rows = derive_data_item_rows(source);
        }

        // read_data_items_in_range() intentionally returns items whose byte
        // spans overlap the requested window. The SQL predicate constrains the
        // item START address, so remove below-bound overlap rows before telling
        // SQLite that the constraint was fully consumed.
        if (window) {
            rows.erase(
                std::remove_if(rows.begin(), rows.end(), [&](const auto& row) {
                    return row.address < window->lo || row.address > window->hi;
                }),
                rows.end());
        }

        std::unordered_map<std::int64_t, size_t> address_slots;
        rows_.reserve(rows.size());
        for (auto& row : rows) {
            const size_t slot = address_slots[row.address]++;
            rows_.emplace_back(
                address_row_ids().encode(row.address, slot), std::move(row));
        }
    }

    bool next() override {
        if (index_ >= rows_.size()) return false;
        current_rowid_ = rows_[index_].first;
        current_ = std::move(rows_[index_].second);
        ++index_;
        return true;
    }

    const model::DataItemRow& current() const override { return current_; }
    std::int64_t rowid() const override { return current_rowid_; }
};

inline xsql::GeneratorTableDef<model::DataItemRow> define_data_items(const std::shared_ptr<Source>& source) {
    return xsql::generator_table<model::DataItemRow>("data_items")
        // A planner estimate must not repeat the same live whole-program scan
        // that execution is about to perform. It is deliberately approximate.
        .estimate_rows([]() { return size_t(100000); })
        .generator([source]() {
            return std::make_unique<DataItemGenerator>(source, std::nullopt);
        })
        .column_int64("addr", [](const model::DataItemRow& r) { return r.address; })
        .column_text_rw(
            "name",
            [](const model::DataItemRow& r) { return r.name; },
            [source](model::DataItemRow& row, const char* name) {
                const std::string next = name ? name : "";
                if (row.name == next) {
                    return true;
                }
                if (!source->rename_data_item(row.address, next)) {
                    report_write_error(source, "UPDATE data_items.name failed: rename_data_item at " +
                        addr_hex(row.address));
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
                    report_write_error(source,
                        "UPDATE data_items.data_type failed: set_data_item_type at " +
                        addr_hex(row.address));
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
                report_write_error(source, "INSERT INTO data_items failed: create_data_item at " +
                    addr_hex(*address));
                return false;
            }
            return true;
        })
        .row_lookup([source](model::DataItemRow& row, std::int64_t raw_rowid) {
            std::int64_t address = 0;
            size_t slot = 0;
            if (!address_row_ids().decode(raw_rowid, address, slot)) {
                return false;
            }
            std::vector<model::DataItemRow> rows;
            if (!source->read_data_items_at(address, rows) || slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .constraint_filter(
            {xsql::required_eq("addr", "")},
            [source](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<model::DataItemRow>> {
                return std::make_unique<DataItemGenerator>(
                    source, memory_bytes_window_from_args(args));
            },
            1.0, 2.0)
        .constraint_filter(
            {xsql::optional_ge("addr"), xsql::optional_gt("addr"),
             xsql::optional_lt("addr"), xsql::optional_le("addr")},
            [source](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<model::DataItemRow>> {
                return std::make_unique<DataItemGenerator>(
                    source, memory_bytes_window_from_args(args));
            },
            10.0, 100.0)
        .build();
}

inline xsql::CachedTableDef<KeyedRow<model::FunctionLocalRow>> define_function_locals(
    const std::shared_ptr<Source>& source,
    const std::shared_ptr<QueryScopeState>& query_scope) {
    // Same O(1) per-function decompilation pattern as define_decomp_lvars.
    return xsql::cached_table<KeyedRow<model::FunctionLocalRow>>("function_locals")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> fns;
            return source->read_functions(fns) ? fns.size() * 3 : size_t(100);
        })
        .cache_builder([source, query_scope](std::vector<KeyedRow<model::FunctionLocalRow>>& out) {
            auto indexed = derive_indexed_function_local_rows(source);
            out = keyed_rows_of(indexed);
            query_scope->function_local_rows.store(std::move(indexed));
        })
        // (func_addr, index in the function) -- the func_addr filter's key.
        .rowid([](const KeyedRow<model::FunctionLocalRow>& r) { return r.row_key; })
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
                        "' at " + addr_hex(row.func_addr));
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
                        "' at " + addr_hex(row.func_addr));
                    return false;
                }
                row.local_type = next;
                return true;
            })
        .column_text("storage", [](const model::FunctionLocalRow& r) { return r.storage; })
        .column_int64("stack_offset", [](const model::FunctionLocalRow& r) { return r.stack_offset; })
        .column_int64("size", [](const model::FunctionLocalRow& r) { return r.size; })
        .row_lookup([source, query_scope](model::FunctionLocalRow& row, std::int64_t raw_rowid) {
            if (query_scope->function_local_rows.lookup(raw_rowid, row)) {
                return true;
            }
            std::int64_t func_addr = 0;
            std::size_t local_index = 0;
            if (!function_slot_row_ids().decode(raw_rowid, func_addr, local_index)) {
                return false;
            }
            auto rows = derive_function_local_rows_for(source, func_addr);
            if (local_index < rows.size()) {
                row = std::move(rows[local_index]);
                return true;
            }
            return false;
        })
        .filter_eq("func_addr",
            [source, query_scope](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                auto rows = derive_function_local_rows_for(source, func_addr);
                std::vector<std::pair<std::int64_t, model::FunctionLocalRow>> indexed;
                indexed.reserve(rows.size());
                for (std::size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(function_slot_row_ids().encode(func_addr, i),
                                         std::move(rows[i]));
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
        .filter_eq("func_addr",
            [source](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                // Only read the one function's stack variables — O(1) RPC.
                auto rows = derive_stack_var_rows_for(source, func_addr);
                return std::make_unique<OwnedRowIterator<model::StackVarRow>>(
                    std::move(rows), column_stack_var);
            }, 1.0, 8.0)
        .index_on("func_addr", [](const model::StackVarRow& r) { return r.func_addr; })
        .index_on("stack_offset", [](const model::StackVarRow& r) { return r.stack_offset; })
        .build();
}

// ---- pcode_ops / pcode_varnodes: the Ghidra leg of the cross-tool low-IR --------------
// P-code per function via the DecompilerService/GetPcode RPC, at a filterable maturity rung
// (high=refined SSA, raw=per-instruction, non-SSA). `pcode_ops` is a GENERATOR (not cached):
// the maturity must be chosen BEFORE the RPC — you cannot fetch high then post-filter to raw —
// so a whole-table cache is a poor fit. Filter by func_addr (O(1) single-function RPC) and
// optionally maturity; an unfiltered scan reads every function once.

// Parsed WHERE func_addr / maturity for the pcode generators.
struct PcodeArgs {
    bool has_func = false;
    std::int64_t func_addr = 0;
    model::PcodeMaturity maturity = model::PcodeMaturity::High;
    bool has_maturity = false;
    bool valid = true;
};
inline PcodeArgs pcode_args_from(const std::vector<xsql::GeneratorConstraintArg>& args,
                                  int func_col, int mat_col, int stage_col) {
    PcodeArgs a;
    auto select_maturity = [&](model::PcodeMaturity maturity) {
        if (a.has_maturity && a.maturity != maturity) {
            a.valid = false;
            return;
        }
        a.maturity = maturity;
        a.has_maturity = true;
    };
    // Every constraint is omit=1: a func_addr no integer equals (4096.5,
    // NULL, 'a') or a NULL/blob maturity or stage matches no row.
    for (const auto& arg : args) {
        if (arg.op != xsql::ConstraintOp::Eq) continue;
        if (arg.column_index == func_col) {
            const std::optional<std::int64_t> key = xsql::exact_int64(arg.value);
            if (!key) {
                a.valid = false;
                continue;
            }
            a.func_addr = *key;
            a.has_func = true;
        } else if (arg.column_index == mat_col) {
            const std::optional<std::string> s = xsql::exact_text(arg.value);
            if (s == "raw") select_maturity(model::PcodeMaturity::Raw);
            else if (s == "high") select_maturity(model::PcodeMaturity::High);
            else a.valid = false;  // unknown rung -> yield nothing
        } else if (arg.column_index == stage_col) {
            const std::optional<std::string> s = xsql::exact_text(arg.value);
            if (s == "raw") select_maturity(model::PcodeMaturity::Raw);
            else if (s == "ssa") select_maturity(model::PcodeMaturity::High);
            else a.valid = false;  // unsupported canonical stage
        }
    }
    return a;
}

// Column order (constraint filter reads func_addr / maturity by index).
enum { kPcodeFuncAddr = 0, kPcodeSeq, kPcodeAddr, kPcodeOp, kPcodeHasOutput,
       kPcodeOutputKind, kPcodeOutputSize, kPcodeInputCount, kPcodeIsSsa,
       kPcodeMaturity, kPcodeStage };
enum { kPvnFuncAddr = 0, kPvnOpSeq, kPvnOperandIndex, kPvnRole, kPvnKind,
       kPvnSpace, kPvnOffset, kPvnSize, kPvnMaturity, kPvnStage };

// Vector-backed generator over pcode ops (derives once from the RPC, then iterates).
class PcodeOpsGenerator : public xsql::Generator<model::PcodeOpRow> {
    std::vector<model::PcodeOpRow> rows_;
    std::size_t idx_ = 0;
    model::PcodeOpRow current_;
public:
    PcodeOpsGenerator(const std::shared_ptr<Source>& source, const PcodeArgs& a) {
        if (!a.valid) return;
        const bool ok = a.has_func
            ? derive_pcode_op_rows_for(source, a.func_addr, a.maturity, rows_)
            : derive_pcode_op_rows(source, a.maturity, rows_);
        if (!ok && xsql::get_vtab_error().empty()) {
            report_read_error_if_any(source, "pcode_ops: failed to read P-code");
        }
    }
    bool next() override { if (idx_ >= rows_.size()) return false; current_ = rows_[idx_++]; return true; }
    const model::PcodeOpRow& current() const override { return current_; }
    std::int64_t rowid() const override {
        return idx_ == 0 ? 0 : static_cast<std::int64_t>(idx_ - 1);
    }
};
class PcodeVarnodesGenerator : public xsql::Generator<model::PcodeVarnodeRow> {
    std::vector<model::PcodeVarnodeRow> rows_;
    std::size_t idx_ = 0;
    model::PcodeVarnodeRow current_;
public:
    PcodeVarnodesGenerator(const std::shared_ptr<Source>& source, const PcodeArgs& a) {
        if (!a.valid) return;
        const bool ok = a.has_func
            ? derive_pcode_varnode_rows_for(
                  source, a.func_addr, a.maturity, rows_)
            : derive_pcode_varnode_rows(source, a.maturity, rows_);
        if (!ok && xsql::get_vtab_error().empty()) {
            report_read_error_if_any(
                source, "pcode_varnodes: failed to read P-code");
        }
    }
    bool next() override { if (idx_ >= rows_.size()) return false; current_ = rows_[idx_++]; return true; }
    const model::PcodeVarnodeRow& current() const override { return current_; }
    std::int64_t rowid() const override {
        // op_seq is only function-local, so packing it with operand_index
        // collides as soon as a whole-program scan reaches another function.
        // This generator is read-only; a scan-local ordinal is the exact SQLite
        // rowid contract we need and stays unique across every emitted row.
        return idx_ == 0 ? 0 : static_cast<std::int64_t>(idx_ - 1);
    }
};

inline xsql::GeneratorTableDef<model::PcodeOpRow> define_pcode_ops(const std::shared_ptr<Source>& source) {
    return xsql::generator_table<model::PcodeOpRow>("pcode_ops")
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> fns;
            return source->read_functions(fns) ? fns.size() * 40 : size_t(200);
        })
        // Unconstrained full scan: every function at the default rung (high).
        .generator([source]() -> std::unique_ptr<xsql::Generator<model::PcodeOpRow>> {
            return std::make_unique<PcodeOpsGenerator>(source, PcodeArgs{});
        })
        .column_int64("func_addr", [](const model::PcodeOpRow& r) { return r.func_addr; })
        .column_int("seq", [](const model::PcodeOpRow& r) { return r.seq; })
        .column("addr", xsql::ColumnType::Integer,
            [](xsql::FunctionContext& ctx, const model::PcodeOpRow& r) {
                if (!r.has_addr) {
                    ctx.result_null();
                } else {
                    ctx.result_int64(r.addr);
                }
            })
        .column_text("op", [](const model::PcodeOpRow& r) { return r.op; })
        .column_int("has_output", [](const model::PcodeOpRow& r) { return r.has_output; })
        .column("output_kind", xsql::ColumnType::Text,
            [](xsql::FunctionContext& ctx, const model::PcodeOpRow& r) {
                r.has_output ? ctx.result_text(r.output_kind) : ctx.result_null();
            })
        .column_int("output_size", [](const model::PcodeOpRow& r) { return r.output_size; })
        .column_int("input_count", [](const model::PcodeOpRow& r) { return r.input_count; })
        .column_int("is_ssa", [](const model::PcodeOpRow& r) { return r.is_ssa; })
        .column_text("maturity", [](const model::PcodeOpRow& r) { return r.maturity; })
        .column_text("stage", [](const model::PcodeOpRow& r) { return r.stage; })
        .constraint_filter(
            {xsql::optional_eq("func_addr"), xsql::optional_eq("maturity"),
             xsql::optional_eq("stage")},
            [source](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<model::PcodeOpRow>> {
                return std::make_unique<PcodeOpsGenerator>(
                    source, pcode_args_from(
                        args, kPcodeFuncAddr, kPcodeMaturity, kPcodeStage));
            }, 1.0, 8.0)
        .build();
}

inline xsql::GeneratorTableDef<model::PcodeVarnodeRow> define_pcode_varnodes(const std::shared_ptr<Source>& source) {
    return xsql::generator_table<model::PcodeVarnodeRow>("pcode_varnodes")
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> fns;
            return source->read_functions(fns) ? fns.size() * 100 : size_t(500);
        })
        .generator([source]() -> std::unique_ptr<xsql::Generator<model::PcodeVarnodeRow>> {
            return std::make_unique<PcodeVarnodesGenerator>(source, PcodeArgs{});
        })
        .column_int64("func_addr", [](const model::PcodeVarnodeRow& r) { return r.func_addr; })
        .column_int("op_seq", [](const model::PcodeVarnodeRow& r) { return r.op_seq; })
        .column_int("operand_index", [](const model::PcodeVarnodeRow& r) { return r.operand_index; })
        .column_text("role", [](const model::PcodeVarnodeRow& r) { return r.role; })
        .column_text("kind", [](const model::PcodeVarnodeRow& r) { return r.kind; })
        .column_text("space", [](const model::PcodeVarnodeRow& r) { return r.space; })
        .column_int64("offset", [](const model::PcodeVarnodeRow& r) { return r.offset; })
        .column_int("size", [](const model::PcodeVarnodeRow& r) { return r.size; })
        .column_text("maturity", [](const model::PcodeVarnodeRow& r) { return r.maturity; })
        .column_text("stage", [](const model::PcodeVarnodeRow& r) { return r.stage; })
        .constraint_filter(
            {xsql::optional_eq("func_addr"), xsql::optional_eq("maturity"),
             xsql::optional_eq("stage")},
            [source](const std::vector<xsql::GeneratorConstraintArg>& args)
                -> std::unique_ptr<xsql::Generator<model::PcodeVarnodeRow>> {
                return std::make_unique<PcodeVarnodesGenerator>(
                    source, pcode_args_from(
                        args, kPvnFuncAddr, kPvnMaturity, kPvnStage));
            }, 1.0, 12.0)
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
        .column_int64("start_addr", [](const model::FunctionChunkRow& r) { return r.start_ea; })
        .column_int64("end_addr", [](const model::FunctionChunkRow& r) { return r.end_ea; })
        .column_text("chunk_kind", [](const model::FunctionChunkRow& r) { return r.chunk_kind; })
        .column_int("is_primary", [](const model::FunctionChunkRow& r) { return r.is_primary; })
        .index_on("func_addr", [](const model::FunctionChunkRow& r) { return r.func_addr; })
        .index_on("start_addr", [](const model::FunctionChunkRow& r) { return r.start_ea; })
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

// JSON array text for a list column, or SQL NULL when the list is empty.
inline std::optional<std::string> json_string_array_or_null(const std::vector<std::string>& values) {
    if (values.empty()) {
        return std::nullopt;
    }
    return xsql::json(values).dump();
}

// The program's real Ghidra options, every category. Analyzer settings are the
// option_scope = 'Analyzers' rows; UPDATE option_value on a settable row writes it
// through to the program (typed by the host: a value the option's type rejects
// fails the statement), persisted by save_database() and reverted by
// discard_changes(). Other categories are read-only.
//
//   UPDATE program_options SET option_value = 'false'
//    WHERE option_scope = 'Analyzers' AND option_key LIKE 'Objective-C%';
//   INSERT INTO analysis_passes(mode) VALUES ('changed');
inline xsql::CachedTableDef<model::ProgramOptionRow> define_program_options(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::ProgramOptionRow>("program_options")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(200); })
        .cache_builder([source](std::vector<model::ProgramOptionRow>& out) {
            out.clear();
            if (!source->read_program_options(out)) {
                report_read_error_if_any(source, "program_options: failed to read program options");
            }
        })
        .column_text("option_key", [](const model::ProgramOptionRow& r) { return r.option_key; })
        .column_text_rw(
            "option_value",
            [](const model::ProgramOptionRow& r) { return r.option_value; },
            [source](model::ProgramOptionRow& row, const char* value) {
                if (row.settable == 0) {
                    xsql::set_vtab_error("program_options: '" + row.option_scope + "' option '" +
                                         row.option_key + "' (" + row.value_type +
                                         ") is not settable");
                    return false;
                }
                const std::string next = value ? value : "";
                if (next == row.option_value) {
                    return true;
                }
                if (!source->set_program_option(row.option_scope, row.option_key, next)) {
                    report_write_error(source, "UPDATE program_options failed for '" + row.option_key + "'");
                    return false;
                }
                row.option_value = next;
                return true;
            })
        .column_text("value_type", [](const model::ProgramOptionRow& r) { return r.value_type; })
        .column_text("option_scope", [](const model::ProgramOptionRow& r) { return r.option_scope; })
        .column_text("description", [](const model::ProgramOptionRow& r) { return r.description; })
        .column_text("default_value", [](const model::ProgramOptionRow& r) { return r.default_value; })
        .column_int("settable", [](const model::ProgramOptionRow& r) { return r.settable; })
        .column_text_nullable("allowed_values", [](const model::ProgramOptionRow& r) {
            return json_string_array_or_null(r.allowed_values);
        })
        .build();
}

// Background auto-analysis jobs of the current program, oldest first. INSERT starts
// one and returns at once -- analysis of a large program runs for minutes, far past
// any query timeout -- and the job then owns the program: other queries fail with
// analysis_running until it finishes. Poll this table (it stays readable) and
// DELETE the running row to cancel. mode is 'changed' (default: what is new or
// changed, or everything if the program was never analyzed) or 'all'.
inline xsql::CachedTableDef<model::AnalysisPassRow> define_analysis_passes(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::AnalysisPassRow>("analysis_passes")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(4); })
        .cache_builder([source](std::vector<model::AnalysisPassRow>& out) {
            out.clear();
            if (!source->read_analysis_passes(out)) {
                report_read_error_if_any(source, "analysis_passes: failed to read analysis jobs");
            }
        })
        .column_int64("pass_id", [](const model::AnalysisPassRow& r) { return r.pass_id; })
        .column_text("mode", [](const model::AnalysisPassRow& r) { return r.mode; })
        .column_text("state", [](const model::AnalysisPassRow& r) { return r.state; })
        .column_int64("started_unix_ms", [](const model::AnalysisPassRow& r) { return r.started_unix_ms; })
        // 0 while the pass is still running.
        .column_int64("ended_unix_ms", [](const model::AnalysisPassRow& r) { return r.ended_unix_ms; })
        .column_int64("elapsed_ms", [](const model::AnalysisPassRow& r) { return r.elapsed_ms; })
        .column_text("message", [](const model::AnalysisPassRow& r) { return r.message; })
        // INSERT: argv is in column order (0 pass_id, 1 mode, 2 state, ...); only
        // mode may be given.
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            for (int i = 0; i < argc; ++i) {
                if (i != 1 && !argv[i].is_null()) {
                    xsql::set_vtab_error(
                        "INSERT INTO analysis_passes takes only mode ('changed' or 'all')");
                    return false;
                }
            }
            const std::string mode = (argc > 1 && !argv[1].is_null()) ? argv[1].as_text() : std::string{};
            model::AnalysisPassRow started;
            if (!source->start_analysis(mode, started)) {
                report_write_error(source, "INSERT INTO analysis_passes failed");
                return false;
            }
            return true;
        })
        .deletable([source](model::AnalysisPassRow& row) {
            if (row.state != "running") {
                xsql::set_vtab_error("analysis_passes: pass " + std::to_string(row.pass_id) +
                                     " is " + row.state + "; only a running pass can be deleted (cancelled)");
                return false;
            }
            if (!source->cancel_analysis(row.pass_id)) {
                report_write_error(source, "DELETE FROM analysis_passes failed for pass " +
                                               std::to_string(row.pass_id));
                return false;
            }
            return true;
        })
        .build();
}

// The program's transaction history: undo stack (tx_position 1 = most recent),
// redo stack (1 = next to redo), and the transaction in progress (tx_kind 'open',
// tx_position 0) with its open sub-transactions. Ghidra records names only; it
// exposes no per-entry revision.
inline xsql::CachedTableDef<model::TransactionRow> define_transactions(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::TransactionRow>("transactions")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(16); })
        .cache_builder([source](std::vector<model::TransactionRow>& out) {
            out.clear();
            if (!source->read_transactions(out)) {
                report_read_error_if_any(source, "transactions: failed to read transaction history");
            }
        })
        .column_int64("tx_position", [](const model::TransactionRow& r) { return r.tx_position; })
        .column_text("tx_name", [](const model::TransactionRow& r) { return r.tx_name; })
        .column_text("tx_kind", [](const model::TransactionRow& r) { return r.tx_kind; })
        .column_text_nullable("open_subtransactions", [](const model::TransactionRow& r) {
            return json_string_array_or_null(r.open_subtransactions);
        })
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
        .column_int64("addr", [](const model::RelocationRow& r) { return r.address; })
        .column_int64("target_addr", [](const model::RelocationRow& r) { return r.target_addr; })
        .column_text("reloc_type", [](const model::RelocationRow& r) { return r.reloc_type; })
        .column_int64("width", [](const model::RelocationRow& r) { return r.width; })
        .column_text("symbol_name", [](const model::RelocationRow& r) { return r.symbol_name; })
        .index_on("addr", [](const model::RelocationRow& r) { return r.address; })
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
        .column_int64("addr", [](const model::ConstantRow& r) { return r.address; })
        .column_int64("func_addr", [](const model::ConstantRow& r) { return r.func_addr; })
        .column_int64("value", [](const model::ConstantRow& r) { return r.value; })
        .column_int64("width", [](const model::ConstantRow& r) { return r.width; })
        .column_text("repr", [](const model::ConstantRow& r) { return r.repr; })
        .column_text("source_kind", [](const model::ConstantRow& r) { return r.source_kind; })
        .filter_eq("func_addr",
            [source](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                return std::make_unique<OwnedRowIterator<model::ConstantRow>>(
                    derive_constant_rows_for(source, func_addr), column_constant);
            },
            5.0,
            32.0)
        .filter_eq("value",
            [](std::int64_t) -> std::unique_ptr<xsql::RowIterator> {
                xsql::set_vtab_error(
                    "unbounded constants.value lookup is disabled because "
                    "Ghidra has no indexed global scalar search; add an exact "
                    "func_addr predicate to use bounded function-local lookup");
                std::vector<model::ConstantRow> rows;
                return std::make_unique<OwnedRowIterator<model::ConstantRow>>(
                    std::move(rows), column_constant);
            },
            8.0,
            16.0)
        .index_on("addr", [](const model::ConstantRow& r) { return r.address; })
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
                report_write_error(source, "INSERT INTO types failed for '" + name + "'");
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
                    report_write_error(source, "UPDATE type_members.member_name failed: rename_type_member for type " +
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
                    report_write_error(source, "UPDATE type_members.member_type failed: set_type_member_type for type " +
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
                    report_write_error(source, "UPDATE type_members.comment failed: set_type_member_comment for type " +
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
                report_write_error(source,
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
                    report_write_error(source, "UPDATE type_enums.name failed: rename_type for enum " +
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
                report_write_error(source, "INSERT INTO type_enums failed for '" + name + "'");
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
                    report_write_error(source, "UPDATE type_enum_members.name failed: rename_type_enum_member");
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
                    report_write_error(source, "UPDATE type_enum_members.value failed: set_type_enum_member_value");
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
                    report_write_error(source, "UPDATE type_enum_members.comment failed: set_type_enum_member_comment");
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
                report_write_error(source,
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
                    report_write_error(source, "UPDATE type_unions.name failed: rename_type for union " +
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
                report_write_error(source, "INSERT INTO type_unions failed for '" + name + "'");
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
                    report_write_error(source, "UPDATE type_aliases.name failed: rename_type for typedef " +
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
                    report_write_error(source, "UPDATE type_aliases.target_type failed: set_type_alias_target for " +
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
                report_write_error(source, "INSERT INTO type_aliases failed for '" + name + "'");
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
                        "UPDATE signatures.name failed at " + addr_hex(row.owner_addr));
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
                        "UPDATE signatures.prototype failed at " + addr_hex(row.owner_addr));
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
        // Planning must not perform the same full live signature scan that
        // cache_builder performs during execution. Three parameters per 10k
        // functions is a stable-enough heuristic for SQLite planning.
        .estimate_rows([]() { return size_t(30000); })
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
                    report_write_error(source,
                        "UPDATE function_params.param_name failed: rename_function_param at " +
                        addr_hex(row.func_addr));
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
                    report_write_error(source,
                        "UPDATE function_params.param_type failed: set_function_param_type at " +
                        addr_hex(row.func_addr));
                    return false;
                }
                row.param_type = next;
                return true;
            })
        .column_text("storage", [](const model::FunctionParamRow& r) { return r.storage; })
        .column_int("is_user_named", [](const model::FunctionParamRow& r) { return r.is_user_named; })
        .row_populator([source](model::FunctionParamRow& row, int argc, xsql::FunctionArg* argv) {
            // argv[0]=old_rowid, argv[1]=new_rowid, argv[2..]=columns
            const std::int64_t func_addr = argc > 2 ? argv[2].as_int64() : 0;
            const std::int64_t ordinal = argc > 3 ? argv[3].as_int64() : 0;
            row.func_addr = func_addr;
            row.ordinal = ordinal;

            std::vector<model::FunctionParamRow> current;
            if (source->read_function_params_at(func_addr, current)) {
                const auto it = std::find_if(current.begin(), current.end(),
                    [ordinal](const model::FunctionParamRow& candidate) {
                        return candidate.ordinal == ordinal;
                    });
                if (it != current.end()) {
                    row = *it;
                }
            }
        })
        // The exact-function iterator uses function-local positional rowids.
        // They are not stable identities in the full function-parameter table,
        // so an UPDATE must reconstruct the target from the real func_addr and
        // ordinal column values rather than treating the iterator position as a
        // global cache position.
        .update_from_column_values()
        .filter_eq("func_addr",
            [source](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::FunctionParamRow> rows;
                source->read_function_params_at(func_addr, rows);
                return std::make_unique<OwnedRowIterator<model::FunctionParamRow>>(
                    std::move(rows), column_function_param);
            },
            2.0,
            8.0)
        .index_on("func_addr", [](const model::FunctionParamRow& r) { return r.func_addr; })
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
        .column_int_nullable("saved_reg_size",
            [](const model::FunctionFrameRow& r) -> std::optional<int> {
                if (!r.saved_reg_size_known) return std::nullopt;
                return static_cast<int>(r.saved_reg_size);
            })
        .column_text_nullable("stack_base_reg",
            [](const model::FunctionFrameRow& r) -> std::optional<std::string> {
                if (r.stack_base_reg.empty()) return std::nullopt;
                return r.stack_base_reg;
            })
        .column_int_nullable("has_frame_pointer",
            [](const model::FunctionFrameRow& r) -> std::optional<int> {
                if (r.has_frame_pointer < 0) return std::nullopt;
                return r.has_frame_pointer;
            })
        .filter_eq("func_addr",
            [source](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                // Only read the one function's frame — O(1) RPC, not O(N).
                auto rows = derive_function_frame_rows_for(source, func_addr);
                return std::make_unique<OwnedRowIterator<model::FunctionFrameRow>>(
                    std::move(rows), column_function_frame);
            }, 1.0, 4.0)
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
        .column_int64("addr", [](const model::TextIndexRow& r) { return r.address; })
        .column_int64("func_addr", [](const model::TextIndexRow& r) { return r.func_addr; })
        .column_text("text", [](const model::TextIndexRow& r) { return r.text; })
        .column_text("norm_text", [](const model::TextIndexRow& r) { return r.norm_text; })
        .index_on("addr", [](const model::TextIndexRow& r) { return r.address; })
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
        .column_int64("addr", [](const model::SearchIndexRow& r) { return r.address; })
        .column_int64("func_addr", [](const model::SearchIndexRow& r) { return r.func_addr; })
        .column_int64("hit_count", [](const model::SearchIndexRow& r) { return r.hit_count; })
        .column_double("rank", [](const model::SearchIndexRow& r) { return r.rank; })
        .filter_eq_text(
            "term",
            [query_scope, source](const std::string& term) -> std::unique_ptr<xsql::RowIterator> {
                auto rows = query_scope->search_index_rows.snapshot();
                if (rows.empty()) {
                    rows = derive_search_index_rows(source);
                    query_scope->search_index_rows.store(rows);
                }
                const std::string needle = term;
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
        .index_on("addr", [](const model::SearchIndexRow& r) { return r.address; })
        .index_on("func_addr", [](const model::SearchIndexRow& r) { return r.func_addr; })
        .build();
}

inline xsql::CachedTableDef<model::XrefIndexRow> define_xref_index(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::XrefIndexRow>("xref_index")
        .no_shared_cache()
        // Cardinality discovery must not materialize the same whole-program
        // reference set that execution may later request.
        .estimate_rows([]() { return size_t(100000); })
        .cache_builder([source](std::vector<model::XrefIndexRow>& out) {
            out = derive_xref_index_rows(source);
        })
        .column_int64("from_addr", [](const model::XrefIndexRow& r) { return r.from_ea; })
        .column_int64("to_addr", [](const model::XrefIndexRow& r) { return r.to_ea; })
        .column_int64("src_func_addr", [](const model::XrefIndexRow& r) { return r.src_func_addr; })
        .column_int64("dst_func_addr", [](const model::XrefIndexRow& r) { return r.dst_func_addr; })
        .column_text("kind", [](const model::XrefIndexRow& r) { return r.kind; })
        .column_int("is_code", [](const model::XrefIndexRow& r) { return r.is_code; })
        .column_int("is_data", [](const model::XrefIndexRow& r) { return r.is_data; })
        .filter_eq("src_func_addr",
            [source](std::int64_t function_address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::XrefRow> refs;
                std::vector<model::XrefIndexRow> rows;
                if (source->read_xrefs_from_function(function_address, refs)) {
                    std::vector<model::FunctionRow> functions;
                    source->read_functions(functions);
                    rows.reserve(refs.size());
                    for (auto& ref : refs) {
                        model::XrefIndexRow row;
                        row.from_ea = ref.from_ea;
                        row.to_ea = ref.to_ea;
                        row.src_func_addr = function_address;
                        const std::int64_t destination =
                            containing_func_addr(functions, ref.to_ea);
                        row.dst_func_addr = destination != 0 ? destination : ref.to_ea;
                        row.kind = std::move(ref.kind);
                        row.is_code = ref.is_code;
                        row.is_data = ref.is_data;
                        rows.push_back(std::move(row));
                    }
                }
                return std::make_unique<OwnedRowIterator<model::XrefIndexRow>>(
                    std::move(rows), column_xref_index);
            },
            4.0,
            128.0)
        .index_on("from_addr", [](const model::XrefIndexRow& r) { return r.from_ea; })
        .index_on("to_addr", [](const model::XrefIndexRow& r) { return r.to_ea; })
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
        .column_text("prototype", [](const model::PseudocodeRow& r) { return r.prototype; })
        .column_int("completed", [](const model::PseudocodeRow& r) { return r.completed; })
        .column_int("is_fallback", [](const model::PseudocodeRow& r) { return r.is_fallback; })
        .column_text("error_message", [](const model::PseudocodeRow& r) { return r.error_message; })
        .filter_eq("func_addr",
            [source](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                auto rows = derive_pseudocode_row_for(source, func_addr);
                return std::make_unique<OwnedRowIterator<model::PseudocodeRow>>(std::move(rows), column_pseudocode);
            }, 1.0, 1.0)
        .filter_eq_text("func_name",
            [source](const std::string& func_name) -> std::unique_ptr<xsql::RowIterator> {
                const std::string needle = func_name;
                std::vector<model::PseudocodeRow> matched_rows;
                for (const auto& fn : find_function_rows_by_name(source, needle)) {
                    auto rows = derive_pseudocode_row_for(source, fn.address);
                    for (auto& row : rows) {
                        row.func_addr = fn.address;
                        row.func_name = fn.name;
                        matched_rows.push_back(std::move(row));
                    }
                }
                return std::make_unique<OwnedRowIterator<model::PseudocodeRow>>(
                    std::move(matched_rows),
                    column_pseudocode);
            }, 4.0, 2.0)
        .build();
}

inline xsql::CachedTableDef<KeyedRow<model::DecompLvarRow>> define_decomp_lvars(
    const std::shared_ptr<Source>& source,
    const std::shared_ptr<QueryScopeState>& query_scope) {
    // Row ids name (func_addr, local_index) (function_slot_row_ids), so
    // filter_eq and row_lookup decompile only the target function instead of
    // ALL functions, which is critical for live sources where each
    // decompilation is an RPC call.

    return xsql::cached_table<KeyedRow<model::DecompLvarRow>>("decomp_lvars")
        .no_shared_cache()
        .estimate_rows([source]() {
            std::vector<model::FunctionRow> funcs;
            return source->read_functions(funcs) ? std::max<size_t>(funcs.size() * 2, 1) : size_t(100);
        })
        .cache_builder([source, query_scope](std::vector<KeyedRow<model::DecompLvarRow>>& out) {
            auto indexed = derive_indexed_decomp_lvar_rows(source);
            out = keyed_rows_of(indexed);
            query_scope->decomp_lvar_rows.store(std::move(indexed));
        })
        // (func_addr, index in the function) -- the func_addr filter's key.
        .rowid([](const KeyedRow<model::DecompLvarRow>& r) { return r.row_key; })
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
                        "' at " + addr_hex(row.func_addr));
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
                        "' at " + addr_hex(row.func_addr));
                    return false;
                }
                row.type = next;
                return true;
            })
        .column_text("storage", [](const model::DecompLvarRow& r) { return r.storage; })
        .column_text("role", [](const model::DecompLvarRow& r) { return r.role; })
        .column_text("func_name", [](const model::DecompLvarRow& r) { return r.func_name; })
        .row_lookup([source, query_scope](model::DecompLvarRow& row, std::int64_t raw_rowid) {
            if (query_scope->decomp_lvar_rows.lookup(raw_rowid, row)) {
                return true;
            }
            std::int64_t func_addr = 0;
            std::size_t local_index = 0;
            if (!function_slot_row_ids().decode(raw_rowid, func_addr, local_index)) {
                return false;
            }
            auto rows = derive_decomp_lvar_rows_for(source, func_addr);
            if (local_index < rows.size()) {
                row = std::move(rows[local_index]);
                return true;
            }
            return false;
        })
        .filter_eq("func_addr",
            [source, query_scope](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                // Only decompile the target function — O(1) RPCs, not O(N_functions).
                auto rows = derive_decomp_lvar_rows_for(source, func_addr);
                std::vector<std::pair<std::int64_t, model::DecompLvarRow>> indexed;
                indexed.reserve(rows.size());
                for (std::size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(function_slot_row_ids().encode(func_addr, i),
                                         std::move(rows[i]));
                }
                query_scope->decomp_lvar_rows.store(indexed);
                return std::make_unique<IndexedOwnedRowIterator<model::DecompLvarRow>>(
                    std::move(indexed),
                    column_decomp_lvar);
            }, 1.0, 4.0)
        .filter_eq_text("func_name",
            [source, query_scope](const std::string& func_name) -> std::unique_ptr<xsql::RowIterator> {
                const std::string needle = func_name;
                std::vector<std::pair<std::int64_t, model::DecompLvarRow>> indexed;
                for (const auto& fn : find_function_rows_by_name(source, needle)) {
                    auto rows = derive_decomp_lvar_rows_for(source, fn.address);
                    indexed.reserve(indexed.size() + rows.size());
                    for (std::size_t i = 0; i < rows.size(); ++i) {
                        auto& row = rows[i];
                        row.func_addr = fn.address;
                        row.func_name = fn.name;
                        indexed.emplace_back(function_slot_row_ids().encode(fn.address, i),
                                             std::move(row));
                    }
                }
                query_scope->decomp_lvar_rows.store(indexed);
                return std::make_unique<IndexedOwnedRowIterator<model::DecompLvarRow>>(
                    std::move(indexed),
                    column_decomp_lvar);
            }, 4.0, 4.0)
        .build();
}

inline xsql::CachedTableDef<KeyedRow<model::DecompCommentRow>> define_decomp_comments(
    const std::shared_ptr<Source>& source,
    const std::shared_ptr<QueryScopeState>& query_scope) {
    return xsql::cached_table<KeyedRow<model::DecompCommentRow>>("decomp_comments")
        .no_shared_cache()
        .estimate_rows([source]() {
            // Cheap estimate based on function count.
            // Do NOT call read_decomp_comments() — it may trigger expensive bulk reads.
            std::vector<model::FunctionRow> funcs;
            return source->read_functions(funcs) ? funcs.size() : size_t(100);
        })
        .cache_builder([source, query_scope](std::vector<KeyedRow<model::DecompCommentRow>>& out) {
            auto indexed = key_decomp_comment_rows(source, derive_decomp_comment_rows(source));
            out = keyed_rows_of(indexed);
            query_scope->decomp_comment_rows.store(std::move(indexed));
        })
        // (func_addr, index in the function) -- the func_addr filter's key.
        .rowid([](const KeyedRow<model::DecompCommentRow>& r) { return r.row_key; })
        .column_int64("func_addr", [](const model::DecompCommentRow& r) { return r.func_addr; })
        .column_int64("addr", [](const model::DecompCommentRow& r) { return r.address; })
        .column_text_rw(
            "comment",
            [](const model::DecompCommentRow& r) { return r.comment; },
            [source](model::DecompCommentRow& row, const char* text) {
                const std::string next = text ? text : "";
                if (!first_comment_write_that_succeeds(
                        "UPDATE decomp_comments.comment failed at " + addr_hex(row.address),
                        {[&] {
                             return !comment_kind_has_flag_form(row.source) &&
                                 source->set_comment_by_kind(row.address, next, row.source);
                         },
                         [&] {
                             return comment_kind_has_flag_form(row.source) &&
                                 source->set_comment(row.address, next,
                                     decomp_comment_source_is_repeatable(row.source));
                         }})) {
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
                        "UPDATE decomp_comments.source failed at " + addr_hex(row.address));
                    return false;
                }
                // Moving the comment means removing it from its previous kind;
                // if that fails the comment now sits under both kinds.
                if (!row.source.empty() &&
                    !delete_decomp_comment(source, row,
                        "UPDATE decomp_comments.source at " + addr_hex(row.address) +
                            ": the comment was written as '" + next + "' but the '" +
                            row.source + "' comment was not removed")) {
                    return false;
                }
                row.source = next;
                return true;
            })
        .deletable([source](model::DecompCommentRow& row) {
            return delete_decomp_comment(
                source, row, "DELETE FROM decomp_comments failed at " + addr_hex(row.address));
        })
        .row_lookup([source, query_scope](model::DecompCommentRow& row, std::int64_t raw_rowid) {
            if (query_scope->decomp_comment_rows.lookup(raw_rowid, row)) {
                return true;
            }
            std::int64_t func_addr = 0;
            std::size_t slot = 0;
            if (!function_slot_row_ids().decode(raw_rowid, func_addr, slot)) {
                return false;
            }
            auto rows = derive_decomp_comment_rows_for(source, func_addr);
            if (slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .filter_eq("func_addr",
            [source, query_scope](std::int64_t func_addr) -> std::unique_ptr<xsql::RowIterator> {
                auto rows = derive_decomp_comment_rows_for(source, func_addr);
                std::vector<std::pair<std::int64_t, model::DecompCommentRow>> indexed;
                indexed.reserve(rows.size());
                for (std::size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(function_slot_row_ids().encode(func_addr, i),
                                         std::move(rows[i]));
                }
                query_scope->decomp_comment_rows.store(indexed);
                return std::make_unique<IndexedOwnedRowIterator<model::DecompCommentRow>>(
                    std::move(indexed),
                    column_decomp_comment);
            }, 1.0, 4.0)
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
            // Advertise the ghidrasql SQL-surface features that exist regardless
            // of what the RPC host reports. The writable `runtime_settings` table
            // is one such ghidrasql-owned feature, so its capability row must be
            // present so the advertised capability matches the now-existing table
            // (offline and live alike).
            model::CapabilityRow rt;
            rt.area = "ghidrasql";
            rt.feature = "feature.runtime_settings";
            rt.state = "available";
            rt.notes = "writable runtime_settings table (UPDATE value); "
                       "timeout_push/timeout_pop are PRAGMAs";
            out.push_back(std::move(rt));
            // Canonical cross-tool byte-pattern search — a pure
            // client-side table over read_bytes, present regardless of host.
            model::CapabilityRow bs;
            bs.area = "ghidrasql";
            bs.feature = "feature.byte_search";
            bs.state = "available";
            bs.notes = "byte_search table (canonical idasql shape; "
                       "WHERE pattern = '<FlexHex>' or byte_search('<FlexHex>'); "
                       "client-side over read_bytes, no Java leg)";
            out.push_back(std::move(bs));
            // Analysis control: real program options (UPDATE the 'Analyzers' rows)
            // and background analysis jobs (INSERT/DELETE analysis_passes).
            model::CapabilityRow ac;
            ac.area = "ghidrasql";
            ac.feature = "feature.analysis_control";
            ac.state = "available";
            ac.notes = "UPDATE program_options.option_value (option_scope='Analyzers'); "
                       "INSERT INTO analysis_passes(mode) starts a background job, "
                       "DELETE of the running row cancels it";
            out.push_back(std::move(ac));
            // Cross-tool low-IR: ghidrasql's leg is the P-code anchor
            // (pcode_ops.op is already the canonical vocabulary). ir_ops is the
            // canonical projection + the ir_v_* semantic views.
            model::CapabilityRow ir;
            ir.area = "ghidrasql";
            ir.feature = "feature.ir_ops";
            ir.state = "available";
            ir.notes = "canonical low-IR (P-code anchor): pcode_ops table + ir_ops view "
                       "(op canonical, native_op provenance, is_ssa=1) + ir_v_calls / "
                       "ir_v_mem_writes / ir_v_mem_reads / ir_v_branches / ir_v_arith; "
                       "scope by func_addr";
            out.push_back(std::move(ir));
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
        // INSERT: persist a benchmark row in the program database (via the
        // AddPerfBenchmark host RPC). argv is indexed by column declaration
        // order: 0 bench_id, 1 query_family, 2 dataset_profile, 3..8 the six
        // double metrics, 9 status.
        .insertable([source](int argc, xsql::FunctionArg* argv) {
            auto text_at = [&](int i) -> std::string {
                return (i < argc && !argv[i].is_null()) ? argv[i].as_text() : std::string{};
            };
            auto double_at = [&](int i) -> double {
                return (i < argc && !argv[i].is_null()) ? argv[i].as_double() : 0.0;
            };
            model::PerfBenchmarkRow row;
            row.bench_id = text_at(0);
            if (row.bench_id.empty()) {
                xsql::set_vtab_error("INSERT INTO perf_benchmarks requires bench_id");
                return false;
            }
            row.query_family = text_at(1);
            row.dataset_profile = text_at(2);
            row.cold_ms_p50 = double_at(3);
            row.cold_ms_p95 = double_at(4);
            row.warm_ms_p50 = double_at(5);
            row.warm_ms_p95 = double_at(6);
            row.throughput_qps = double_at(7);
            row.regression_pct = double_at(8);
            row.status = text_at(9);
            if (!source->add_perf_benchmark(row)) {
                report_write_error(source, "INSERT INTO perf_benchmarks failed for bench_id '" + row.bench_id + "'");
                return false;
            }
            return true;
        })
        // DELETE: remove a benchmark row by bench_id via a single host-side
        // DeletePerfBenchmark RPC (one transaction per row). A bare
        // `DELETE FROM perf_benchmarks` with no WHERE removes every row the same
        // way — one DeletePerfBenchmark RPC per row, not a single bulk clear.
        .deletable([source](model::PerfBenchmarkRow& row) {
            if (!source->delete_perf_benchmark(row.bench_id)) {
                report_write_error(source, "DELETE FROM perf_benchmarks failed for bench_id '" + row.bench_id + "'");
                return false;
            }
            return true;
        })
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

// Hidden "true_believers" easter-egg table — early adopters decoded at query
// time from a packed blob.
struct TrueBelieverRow {
    std::string handle;
    std::string name;
};

inline xsql::CachedTableDef<TrueBelieverRow> define_true_believers() {
    return xsql::cached_table<TrueBelieverRow>("true_believers")
        .no_shared_cache()
        .estimate_rows([]() { return ::true_believers::rows().size(); })
        .cache_builder([](std::vector<TrueBelieverRow>& out) {
            out.clear();
            for (const auto& [handle, name] : ::true_believers::rows())
                out.push_back({handle, name});
        })
        .column_text("handle", [](const TrueBelieverRow& r) { return r.handle; })
        .column_text("name", [](const TrueBelieverRow& r) { return r.name; })
        .build();
}

// The writable `runtime_settings` table is built by the shared libxsql helper
// (xsql::runtime::define_runtime_settings_table) over the registry's
// RuntimeSettingsCore -- ghidrasql adds no tool-specific keys, so there is no
// per-tool definition here (see the Impl ctor). The registry always holds a real
// core (a fresh default one for data-only registries), so the table is uniformly
// writable and isolated per registry.

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

inline xsql::CachedTableDef<KeyedRow<model::BreakpointRow>> define_breakpoints(
    const std::shared_ptr<Source>& source,
    const std::shared_ptr<QueryScopeState>& query_scope) {
    return xsql::cached_table<KeyedRow<model::BreakpointRow>>("breakpoints")
        .no_shared_cache()
        .cache_builder([source, query_scope](std::vector<KeyedRow<model::BreakpointRow>>& out) {
            std::vector<model::BreakpointRow> rows;
            if (!source->read_breakpoints(rows)) { rows.clear(); }
            auto indexed = key_by_address_slot(std::move(rows), address_row_ids());
            out = keyed_rows_of(indexed);
            query_scope->breakpoint_rows.store(std::move(indexed));
        })
        // (address, index at that address) -- the addr filter's key.
        .rowid([](const KeyedRow<model::BreakpointRow>& r) { return r.row_key; })
        .column_int64("addr", [](const model::BreakpointRow& r) { return r.address; })
        .column_int_rw(
            "enabled",
            [](const model::BreakpointRow& r) { return r.enabled; },
            [source](model::BreakpointRow& row, int value) {
                if (!source->set_breakpoint_enabled(row.address, value != 0)) {
                    report_write_error(source, "UPDATE breakpoints.enabled failed at " + addr_hex(row.address));
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
                    report_write_error(source, "UPDATE breakpoints.type failed at " + addr_hex(row.address));
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
                    report_write_error(source, "UPDATE breakpoints.size failed at " + addr_hex(row.address));
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
                    report_write_error(source, "UPDATE breakpoints.condition failed at " + addr_hex(row.address));
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
                    report_write_error(source, "UPDATE breakpoints.group failed at " + addr_hex(row.address));
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
                report_write_error(source, "DELETE FROM breakpoints failed at " + addr_hex(row.address));
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
                report_write_error(source, "INSERT INTO breakpoints failed at " + addr_hex(address));
                return false;
            }
            if (argc > 1 && !argv[1].is_null() && argv[1].as_int() == 0) {
                return source->set_breakpoint_enabled(address, false);
            }
            return true;
        })
        .row_lookup([source, query_scope](model::BreakpointRow& row, std::int64_t raw_rowid) {
            if (query_scope->breakpoint_rows.lookup(raw_rowid, row)) {
                return true;
            }
            std::int64_t address = 0;
            size_t slot = 0;
            if (!address_row_ids().decode(raw_rowid, address, slot)) {
                return false;
            }
            std::vector<model::BreakpointRow> rows;
            if (!source->read_breakpoints_at(address, rows) || slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .filter_eq("addr",
            [source, query_scope](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::BreakpointRow> rows;
                source->read_breakpoints_at(address, rows);
                std::vector<std::pair<std::int64_t, model::BreakpointRow>> indexed;
                indexed.reserve(rows.size());
                for (size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(address_row_ids().encode(address, i), std::move(rows[i]));
                }
                query_scope->breakpoint_rows.store(indexed);
                return std::make_unique<IndexedOwnedRowIterator<model::BreakpointRow>>(
                    std::move(indexed),
                    column_breakpoint);
            }, 1.0, 2.0)
        .build();
}

inline xsql::CachedTableDef<KeyedRow<model::BookmarkRow>> define_bookmarks(
    const std::shared_ptr<Source>& source,
    const std::shared_ptr<QueryScopeState>& query_scope) {
    return xsql::cached_table<KeyedRow<model::BookmarkRow>>("bookmarks")
        .no_shared_cache()
        .cache_builder([source, query_scope](std::vector<KeyedRow<model::BookmarkRow>>& out) {
            std::vector<model::BookmarkRow> rows;
            if (!source->read_bookmarks(rows)) { rows.clear(); }
            auto indexed = key_by_address_slot(std::move(rows), address_row_ids());
            out = keyed_rows_of(indexed);
            query_scope->bookmark_rows.store(std::move(indexed));
        })
        // (address, index at that address) -- the addr filter's key.
        .rowid([](const KeyedRow<model::BookmarkRow>& r) { return r.row_key; })
        .column_int64("addr", [](const model::BookmarkRow& r) { return r.address; })
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
                    report_write_error(source, "UPDATE bookmarks.type failed at " + addr_hex(row.address));
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
                    report_write_error(source, "UPDATE bookmarks.category failed at " + addr_hex(row.address));
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
                    report_write_error(source, "UPDATE bookmarks.comment failed at " + addr_hex(row.address));
                    return false;
                }
                row.comment = value ? value : "";
                return true;
            })
        .deletable([source](model::BookmarkRow& row) {
            if (!source->delete_bookmark(row.address, row.type, row.category)) {
                report_write_error(source, "DELETE FROM bookmarks failed at " + addr_hex(row.address));
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
                report_write_error(source, "INSERT INTO bookmarks failed at " + addr_hex(address));
                return false;
            }
            return true;
        })
        .row_lookup([source, query_scope](model::BookmarkRow& row, std::int64_t raw_rowid) {
            if (query_scope->bookmark_rows.lookup(raw_rowid, row)) {
                return true;
            }
            std::int64_t address = 0;
            size_t slot = 0;
            if (!address_row_ids().decode(raw_rowid, address, slot)) {
                return false;
            }
            std::vector<model::BookmarkRow> rows;
            if (!source->read_bookmarks_at(address, rows) || slot >= rows.size()) {
                return false;
            }
            row = std::move(rows[slot]);
            return true;
        })
        .filter_eq("addr",
            [source, query_scope](std::int64_t address) -> std::unique_ptr<xsql::RowIterator> {
                std::vector<model::BookmarkRow> rows;
                source->read_bookmarks_at(address, rows);
                std::vector<std::pair<std::int64_t, model::BookmarkRow>> indexed;
                indexed.reserve(rows.size());
                for (size_t i = 0; i < rows.size(); ++i) {
                    indexed.emplace_back(address_row_ids().encode(address, i), std::move(rows[i]));
                }
                query_scope->bookmark_rows.store(indexed);
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
                    "' at " + addr_hex(row.func_addr));
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
                    "' at " + addr_hex(func_addr));
                return false;
            }
            return true;
        })
        .build();
}

// binary — orientation/metadata table, canonical key/value/type shape (one
// row per fact). Columns: (key TEXT, value TEXT, type TEXT), type in
// {string, hex, bool, int}. Canonical core keys shared with
// idasql/bnsql/r2sql: tool_name, tool_version, processor, filetype,
// image_base, entry_point, min_addr, max_addr, is_64bit, bits, endianness,
// filename, summary, md5, sha256 (hashes omitted when the host reports
// none). ghidrasql extras: program_name, program_path, language_id,
// compiler_spec, analysis_id, host_service, is_headless, revision.
inline xsql::CachedTableDef<model::BinaryFactRow> define_binary(const std::shared_ptr<Source>& source) {
    return xsql::cached_table<model::BinaryFactRow>("binary")
        .no_shared_cache()
        .estimate_rows([]() { return size_t(22); })
        .cache_builder([source](std::vector<model::BinaryFactRow>& out) {
            out.clear();
            model::ProgramInfoRow info;
            if (!source->read_program_info(info)) {
                return;
            }

            auto add = [&out](const char* key, std::string value, const char* type) {
                out.push_back({key, std::move(value), type});
            };
            auto hex_i64 = [](std::int64_t v) -> std::string {
                char buf[32];
                std::snprintf(buf, sizeof(buf), "0x%llx",
                              static_cast<unsigned long long>(v));
                return buf;
            };

            std::string processor, endian;
            int bits = 0;
            const bool lang_ok =
                parse_language_id(info.language_id, processor, endian, bits);

            // min/max mapped address from the memory map (same RPC cost class
            // as the memory_blocks table); omitted when no blocks are known.
            bool have_range = false;
            std::int64_t min_addr = 0, max_addr = 0;
            {
                std::vector<model::MemoryBlockRow> blocks;
                if (source->read_memory_blocks(blocks)) {
                    for (const auto& b : blocks) {
                        // Compare as unsigned: to_i64 no longer clamps, so a high
                        // VA (>= 2^63, e.g. an ARM64 kernel address) round-trips as
                        // a negative int64. Signed < / > would mis-order such a
                        // block against low ones, yielding a wrong min/max.
                        if (!have_range ||
                            static_cast<std::uint64_t>(b.start_ea) <
                                static_cast<std::uint64_t>(min_addr))
                            min_addr = b.start_ea;
                        if (!have_range ||
                            static_cast<std::uint64_t>(b.end_ea) >
                                static_cast<std::uint64_t>(max_addr))
                            max_addr = b.end_ea;
                        have_range = true;
                    }
                }
            }

            // summary first: agents doing `SELECT * FROM binary` see the
            // digest up top.
            {
                std::string s = lang_ok ? processor : info.language_id;
                if (bits != 0) s += " " + std::to_string(bits) + "-bit";
                if (!info.program_name.empty()) s += " | " + info.program_name;
                s += " | rev " + std::to_string(info.revision);
                add("summary", s, "string");
            }

            // Tool identity. tool_name is the constant "ghidrasql"; the RPC
            // host's service name (the old tool_name column's value, e.g.
            // "ghidra"/"libghidra") moved to the host_service extra.
            add("tool_name", "ghidrasql", "string");
            add("tool_version", GHIDRASQL_VERSION, "string");

            // Canonical core keys.
            if (lang_ok) {
                add("processor", processor, "string");
            }
            if (!info.executable_format.empty()) {
                add("filetype", info.executable_format, "string");
            }
            add("image_base", hex_i64(info.image_base), "hex");
            if (info.has_entry_point) {
                add("entry_point", hex_i64(info.entry_point), "hex");
            }
            if (have_range) {
                add("min_addr", hex_i64(min_addr), "hex");
                add("max_addr", hex_i64(max_addr), "hex");
            }
            if (lang_ok) {
                add("is_64bit", bits == 64 ? "true" : "false", "bool");
                add("bits", std::to_string(bits), "int");
                add("endianness", endian == "BE" ? "big" : "little", "string");
            }
            add("filename", info.program_name, "string");

            // Best-effort core hashes: omitted when the host reports none.
            if (!info.md5.empty()) add("md5", info.md5, "string");
            if (!info.sha256.empty()) add("sha256", info.sha256, "string");

            // ghidrasql extras.
            add("program_name", info.program_name, "string");
            add("program_path", info.program_path, "string");
            add("language_id", info.language_id, "string");
            add("compiler_spec", info.compiler_spec, "string");
            add("analysis_id", info.analysis_id, "string");
            add("host_service", info.tool_name, "string");
            add("is_headless", info.is_headless != 0 ? "true" : "false", "bool");
            add("revision", std::to_string(info.revision), "int");
        })
        .column_text("key", [](const model::BinaryFactRow& r) { return r.key; })
        .column_text("value", [](const model::BinaryFactRow& r) { return r.value; })
        .column_text("type", [](const model::BinaryFactRow& r) { return r.type; })
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
    explicit Impl(std::shared_ptr<Source> source_,
                  std::shared_ptr<xsql::runtime::RuntimeSettingsCore> settings_)
        : query_scope(std::make_shared<QueryScopeState>())
        , source(std::move(source_))
        // Always hold a real core: a data-only registry (null settings_) gets a
        // fresh default one so runtime_settings is uniformly writable + isolated.
        , settings(settings_ ? std::move(settings_)
                             : std::make_shared<xsql::runtime::RuntimeSettingsCore>())
        , project_files(define_project_files(source))
        , project_programs(define_project_programs(source))
        , funcs(define_funcs(source))
        , leaf_funcs(define_leaf_funcs(source))
        , segments(define_segments(source))
        , memory_blocks(define_memory_blocks(source))
        , memory_bytes(define_memory_bytes(source))
        , byte_search(define_byte_search(source))
        , names(define_names(source, query_scope))
        , imports(define_imports(source))
        , exports(define_exports(source))
        , strings(define_strings(source))
        , string_refs(define_string_refs(source))
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
        , instruction_operands(define_instruction_operands(source))
        , comments(define_comments(source, query_scope))
        , data_items(define_data_items(source))
        , function_locals(define_function_locals(source, query_scope))
        , stack_vars(define_stack_vars(source))
        , pcode_ops(define_pcode_ops(source))
        , pcode_varnodes(define_pcode_varnodes(source))
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
        , decomp_comments(define_decomp_comments(source, query_scope))
        , decomp_tokens(define_decomp_tokens(source))
        , breakpoints(define_breakpoints(source, query_scope))
        , bookmarks(define_bookmarks(source, query_scope))
        , function_tags(define_function_tags(source))
        , function_tag_mappings(define_function_tag_mappings(source))
        , sql_capabilities(define_sql_capabilities(source))
        , parity_findings(define_parity_findings(source))
        , perf_benchmarks(define_perf_benchmarks(source))
        , live_meta(define_live_meta(source))
        , binary(define_binary(source))
        , runtime_settings(xsql::runtime::define_runtime_settings_table(
              *settings, "ghidrasql"))
        , true_believers(define_true_believers()) {}

    void register_all(xsql::Database& db) {
        register_cached(db, "project_files", &project_files);
        register_cached(db, "project_programs", &project_programs);
        register_cached(db, "funcs", &funcs);
        register_cached(db, "leaf_funcs", &leaf_funcs);
        register_cached(db, "segments", &segments);
        register_cached(db, "memory_blocks", &memory_blocks);
        register_generator(db, "bytes", &memory_bytes);
        register_generator(db, "byte_search", &byte_search);
        register_cached(db, "names", &names);
        register_cached(db, "imports", &imports);
        register_cached(db, "entries", &exports);
        register_cached(db, "strings", &strings);
        register_cached(db, "string_refs", &string_refs);
        register_cached(db, "xrefs", &xrefs);
        register_cached(db, "call_edges", &call_edges);
        register_cached(db, "function_calls", &function_calls);
        register_cached(db, "blocks", &blocks);
        register_cached(db, "cfg_edges", &cfg_edges);
        register_cached(db, "loops", &loops);
        register_cached(db, "switch_tables", &switch_tables);
        register_cached(db, "dominators", &dominators);
        register_cached(db, "post_dominators", &post_dominators);
        register_generator(db, "instructions", &instructions);
        register_cached(db, "instruction_operands", &instruction_operands);
        register_cached(db, "comments", &comments);
        register_generator(db, "data_items", &data_items);
        register_cached(db, "function_locals", &function_locals);
        register_cached(db, "stack_vars", &stack_vars);
        register_generator(db, "pcode_ops", &pcode_ops);
        register_generator(db, "pcode_varnodes", &pcode_varnodes);
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
        register_cached(db, "binary", &binary);
        register_cached(db, "runtime_settings", &runtime_settings);
        register_cached(db, "true_believers", &true_believers);
        create_entity_views(db);
    }

    void invalidate_all() const {
        query_scope->reset_all();
        project_files.invalidate_cache();
        project_programs.invalidate_cache();
        funcs.invalidate_cache();
        leaf_funcs.invalidate_cache();
        segments.invalidate_cache();
        memory_blocks.invalidate_cache();
        // memory_bytes is a generator table: it derives fresh on every query,
        // so there is no cache to invalidate (query_scope->reset_all() above
        // already covers its per-query scope state).
        names.invalidate_cache();
        imports.invalidate_cache();
        exports.invalidate_cache();
        strings.invalidate_cache();
        string_refs.invalidate_cache();
        xrefs.invalidate_cache();
        call_edges.invalidate_cache();
        function_calls.invalidate_cache();
        blocks.invalidate_cache();
        cfg_edges.invalidate_cache();
        loops.invalidate_cache();
        switch_tables.invalidate_cache();
        dominators.invalidate_cache();
        post_dominators.invalidate_cache();
        // instructions is a per-query generator; there is no cache to invalidate.
        instruction_operands.invalidate_cache();
        comments.invalidate_cache();
        // data_items is a generator table: it derives fresh on every query.
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
        binary.invalidate_cache();
        runtime_settings.invalidate_cache();
        true_believers.invalidate_cache();
    }

    bool invalidate_table(const std::string& name) const {
        query_scope->reset_for_table(name);
        if (name == "funcs") {
            funcs.invalidate_cache();
            return true;
        }
        if (name == "leaf_funcs") {
            leaf_funcs.invalidate_cache();
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
        if (name == "bytes") {
            // Generator table: derives fresh per query, so invalidation is a
            // successful no-op (reset_for_table above already ran). Kept as an
            // explicit branch so cache_invalidate('bytes') still
            // resolves the registered table (schema-conformance contract).
            return true;
        }
        if (name == "byte_search") {
            // Generator table (client-side pattern search): fresh per query, so
            // invalidation is a successful no-op — the explicit branch keeps
            // cache_invalidate('byte_search') resolving (schema-conformance).
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
        if (name == "entries") {
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
            // Per-query generator; there is no persistent cache to invalidate.
            return true;
        }
        if (name == "instruction_operands") {
            instruction_operands.invalidate_cache();
            return true;
        }
        if (name == "comments") {
            comments.invalidate_cache();
            return true;
        }
        if (name == "data_items") {
            // Per-query generator; there is no persistent cache to invalidate.
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
        if (name == "pcode_ops" || name == "pcode_varnodes") {
            // Per-query generators have no persistent cache. The successful
            // no-op keeps schema discovery and cache_invalidate(name) in
            // lockstep with every registered public table.
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
        if (name == "string_refs") {
            string_refs.invalidate_cache();
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
        if (name == "binary") {
            binary.invalidate_cache();
            return true;
        }
        if (name == "runtime_settings") {
            runtime_settings.invalidate_cache();
            return true;
        }
        if (name == "true_believers") {
            true_believers.invalidate_cache();
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
        // Native canonical registration: the vtable module IS the canonical table
        // name (no ghidra_ prefix, no alias) -- one true name per table.
        db.register_cached_table(table_name, def);
        db.create_table(table_name, table_name);
    }

    template <typename RowData>
    static void register_generator(
        xsql::Database& db,
        const char* table_name,
        const xsql::GeneratorTableDef<RowData>* def)
    {
        db.register_generator_table(table_name, def);
        db.create_table(table_name, table_name);
    }

    static void register_index(
        xsql::Database& db,
        const char* table_name,
        const xsql::VTableDef* def)
    {
        db.register_table(table_name, def);
        db.create_table(table_name, table_name);
    }

public:
    std::shared_ptr<QueryScopeState> query_scope;
    std::shared_ptr<Source> source;
    std::shared_ptr<xsql::runtime::RuntimeSettingsCore> settings;
    xsql::CachedTableDef<model::ProjectFileRow> project_files;
    xsql::CachedTableDef<model::ProjectFileRow> project_programs;
    xsql::CachedTableDef<model::FunctionRow> funcs;
    xsql::CachedTableDef<model::FunctionRow> leaf_funcs;
    xsql::CachedTableDef<model::SegmentRow> segments;
    xsql::CachedTableDef<model::MemoryBlockRow> memory_blocks;
    // Streaming generator table (derives fresh per query; no cache to invalidate).
    xsql::GeneratorTableDef<model::MemoryByteRow> memory_bytes;
    xsql::GeneratorTableDef<ByteSearchRow> byte_search;
    xsql::CachedTableDef<KeyedRow<model::SymbolRow>> names;
    xsql::CachedTableDef<model::ImportRow> imports;
    xsql::CachedTableDef<model::ExportRow> exports;
    xsql::CachedTableDef<model::StringRow> strings;
    xsql::CachedTableDef<model::StringRefRow> string_refs;
    xsql::CachedTableDef<model::XrefRow> xrefs;
    xsql::CachedTableDef<model::CallEdgeRow> call_edges;
    xsql::CachedTableDef<model::FunctionCallRow> function_calls;
    xsql::CachedTableDef<model::BlockRow> blocks;
    xsql::CachedTableDef<model::CfgEdgeRow> cfg_edges;
    xsql::CachedTableDef<model::LoopRow> loops;
    xsql::CachedTableDef<model::SwitchTableRow> switch_tables;
    xsql::CachedTableDef<model::DominatorRow> dominators;
    xsql::CachedTableDef<model::PostDominatorRow> post_dominators;
    xsql::GeneratorTableDef<model::InstructionRow> instructions;
    xsql::CachedTableDef<model::InstructionOperandRow> instruction_operands;
    xsql::CachedTableDef<KeyedRow<model::CommentRow>> comments;
    xsql::GeneratorTableDef<model::DataItemRow> data_items;
    xsql::CachedTableDef<KeyedRow<model::FunctionLocalRow>> function_locals;
    xsql::CachedTableDef<model::StackVarRow> stack_vars;
    xsql::GeneratorTableDef<model::PcodeOpRow> pcode_ops;
    xsql::GeneratorTableDef<model::PcodeVarnodeRow> pcode_varnodes;
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
    xsql::CachedTableDef<KeyedRow<model::DecompLvarRow>> decomp_lvars;
    xsql::CachedTableDef<KeyedRow<model::DecompCommentRow>> decomp_comments;
    xsql::CachedTableDef<model::DecompTokenRow> decomp_tokens;
    xsql::CachedTableDef<KeyedRow<model::BreakpointRow>> breakpoints;
    xsql::CachedTableDef<KeyedRow<model::BookmarkRow>> bookmarks;
    xsql::CachedTableDef<model::FunctionTagRow> function_tags;
    xsql::CachedTableDef<model::FunctionTagMappingRow> function_tag_mappings;
    xsql::CachedTableDef<model::CapabilityRow> sql_capabilities;
    xsql::CachedTableDef<model::ParityFindingRow> parity_findings;
    xsql::CachedTableDef<model::PerfBenchmarkRow> perf_benchmarks;
    xsql::CachedTableDef<model::LiveMetaRow> live_meta;
    xsql::CachedTableDef<model::BinaryFactRow> binary;
    xsql::CachedTableDef<xsql::runtime::RuntimeSettingEntry> runtime_settings;
    xsql::CachedTableDef<TrueBelieverRow> true_believers;
};


TableRegistry::TableRegistry(
    std::shared_ptr<Source> source,
    std::shared_ptr<xsql::runtime::RuntimeSettingsCore> settings)
    : impl_(std::make_unique<Impl>(std::move(source), std::move(settings))) {}

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
