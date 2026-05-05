// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <ghidrasql/ghidrasql.hpp>
#include <ghidrasql/source.hpp>

#include "internal/entities.hpp"
#include "internal/functions.hpp"

#include <xsql/database.hpp>
#include <xsql/json.hpp>
#include <xsql/script.hpp>

#include <algorithm>
#include <cctype>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ghidrasql {

const std::string& Row::operator[](size_t i) const {
    return values[i];
}

size_t Row::size() const {
    return values.size();
}

size_t QueryResult::row_count() const {
    return rows.size();
}

bool QueryResult::empty() const {
    return rows.empty();
}

class QueryEngine::Impl {
public:
    explicit Impl(std::shared_ptr<Source> source = nullptr)
        : source_(std::move(source)) {
        if (!source_) {
            error_ = "QueryEngine created without a data source";
            return;
        }
        init();
    }

    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) noexcept = default;
    Impl& operator=(Impl&&) noexcept = default;
    ~Impl() = default;

    QueryResult query(const std::string& sql) {
        refresh_if_needed();
        return execute_sql(sql);
    }

    bool execute(const std::string& sql) {
        return query(sql).success;
    }

    bool execute_script(
        const std::string& script,
        std::vector<QueryResult>& results,
        std::string& error)
    {
        results.clear();
        error.clear();

        if (!db_.is_open()) {
            error_ = "database is not open";
            error = error_;
            return false;
        }

        std::vector<std::string> statements;
        if (!xsql::collect_statements(script, statements, error)) {
            error_ = error;
            return false;
        }
        if (statements.empty()) {
            error_.clear();
            return true;
        }

        refresh_if_needed();
        BatchScope batch_scope(*this);

        for (const auto& stmt : statements) {
            bool readonly = true;
            if (!statement_is_readonly(stmt, readonly, error)) {
                error_ = error;
                return false;
            }

            if (pending_batch_refresh_ && readonly) {
                flush_batch_refresh();
            }

            auto token_before = current_freshness_token();
            const std::int64_t revision_before =
                token_before ? token_before->modification_number : current_revision();
            auto result = execute_sql(stmt);
            results.push_back(result);
            if (!result.success) {
                error = result.error;
                return false;
            }

            auto token_after = current_freshness_token();
            const bool source_changed = token_before && token_after
                ? *token_after != *token_before
                : current_revision() != revision_before;
            if (!readonly || source_changed) {
                pending_batch_refresh_ = true;
            }
        }

        if (pending_batch_refresh_) {
            flush_batch_refresh();
        }

        error_.clear();
        return true;
    }

    std::string scalar(const std::string& sql) {
        auto result = query(sql);
        if (!result.success || result.rows.empty() || result.rows.front().values.empty()) {
            return {};
        }
        return result.rows.front().values.front();
    }

    std::vector<std::string> list_tables() {
        refresh_if_needed();
        std::vector<std::string> out;
        auto r = db_.query(
            "SELECT name FROM sqlite_master "
            "WHERE type IN ('table','view') "
            "ORDER BY type DESC, name");
        if (!r.ok()) {
            return out;
        }
        for (const auto& row : r.rows) {
            if (!row.values.empty()) {
                out.push_back(row.values[0]);
            }
        }
        return out;
    }

    std::string schema_for(const std::string& table) {
        refresh_if_needed();
        if (!is_safe_identifier(table)) {
            return "invalid table name";
        }

        auto sql = db_.query(
            "SELECT sql FROM sqlite_master WHERE name = '" + table + "' LIMIT 1");
        if (sql.ok() && !sql.empty() && !sql.rows[0].values.empty()) {
            return sql.rows[0].values[0];
        }

        auto pragma = db_.query("PRAGMA table_info(" + table + ")");
        if (!pragma.ok() || pragma.empty()) {
            return "no schema found for " + table;
        }

        std::string text = "CREATE TABLE " + table + "(\n";
        for (const auto& row : pragma.rows) {
            if (row.values.size() >= 3) {
                text += "  " + row.values[1] + " " + row.values[2] + ",\n";
            }
        }
        if (text.size() >= 2 && text[text.size() - 2] == ',') {
            text.erase(text.size() - 2, 1);
        }
        text += ");";
        return text;
    }

    std::string info() {
        refresh_if_needed();
        auto r = db_.query("SELECT tool_name, program_name, language_id, revision FROM db_info LIMIT 1");
        if (!r.ok() || r.empty() || r.rows[0].values.size() < 4) {
            return "ghidrasql: no db_info available";
        }
        return "tool=" + r.rows[0].values[0] +
               ", program=" + r.rows[0].values[1] +
               ", language=" + r.rows[0].values[2] +
               ", revision=" + r.rows[0].values[3];
    }

    bool is_valid() const { return db_.is_open(); }
    const std::string& error() const { return error_; }

    xsql::Database& database() { return db_; }
    const xsql::Database& database() const { return db_; }

    void set_query_timeout_ms(int ms) { query_timeout_ms_ = ms; }
    int query_timeout_ms() const { return query_timeout_ms_; }

    bool refresh() {
        if (!source_) {
            return false;
        }
        const bool ok = source_->refresh();
        if (ok) {
            invalidate_all_tables();
            update_last_seen_revision();
        }
        pending_batch_refresh_ = false;
        return ok;
    }

private:
    struct BatchScope {
        explicit BatchScope(Impl& impl)
            : impl_(impl)
            , previous_in_batch_(impl.in_batch_)
            , previous_pending_refresh_(impl.pending_batch_refresh_) {
            impl_.in_batch_ = true;
            impl_.pending_batch_refresh_ = false;
        }

        ~BatchScope() {
            impl_.in_batch_ = previous_in_batch_;
            impl_.pending_batch_refresh_ = previous_pending_refresh_;
        }

    private:
        Impl& impl_;
        bool previous_in_batch_ = false;
        bool previous_pending_refresh_ = false;
    };

    static bool is_safe_identifier(const std::string& text) {
        if (text.empty() || text.size() > 128) {
            return false;
        }
        return std::all_of(text.begin(), text.end(), [](unsigned char c) {
            return std::isalnum(c) || c == '_';
        });
    }

    QueryResult execute_sql(const std::string& sql) {
        QueryResult result;
        if (!db_.is_open()) {
            error_ = "database is not open";
            result.error = error_;
            return result;
        }

        xsql::Result raw;
        if (query_timeout_ms_ > 0) {
            xsql::QueryOptions opts;
            opts.timeout_ms = query_timeout_ms_;
            raw = db_.query(sql, opts);
        } else {
            raw = db_.query(sql);
        }
        error_ = raw.error;
        result.columns = std::move(raw.columns);
        result.rows.reserve(raw.rows.size());
        for (auto& raw_row : raw.rows) {
            result.rows.push_back(Row{std::move(raw_row.values)});
        }
        result.error = raw.error;
        result.success = raw.ok();
        result.timed_out = raw.timed_out;
        result.partial = raw.partial;
        result.elapsed_ms = raw.elapsed_ms;
        return result;
    }

    bool statement_is_readonly(const std::string& sql, bool& readonly, std::string& error) {
        readonly = true;
        error.clear();

        auto stmt = db_.prepare_statement(sql);
        if (!stmt.valid()) {
            error = stmt.error();
            return false;
        }

        readonly = stmt.is_readonly();
        return true;
    }

    std::int64_t current_revision() const {
        if (!source_) {
            return 0;
        }
        SourceFreshnessToken token;
        if (source_->read_freshness_token(token)) {
            return token.modification_number;
        }
        std::int64_t revision = 0;
        if (source_->read_program_revision(revision)) {
            return revision;
        }
        model::ProgramInfoRow info;
        return source_->read_program_info(info) ? info.revision : 0;
    }

    std::optional<SourceFreshnessToken> current_freshness_token() const {
        if (!source_) {
            return std::nullopt;
        }
        SourceFreshnessToken token;
        if (!source_->read_freshness_token(token)) {
            return std::nullopt;
        }
        return token;
    }

    static xsql::json freshness_token_json(const SourceFreshnessToken& token) {
        xsql::json j;
        j["program_id"] = token.program_id;
        j["modification_number"] = token.modification_number;
        j["program_path"] = token.program_path;
        j["file_id"] = token.file_id;
        j["file_version"] = token.file_version;
        j["file_last_modified_time"] = token.file_last_modified_time;
        return j;
    }

    void flush_batch_refresh() {
        invalidate_all_tables();
        update_last_seen_revision();
        pending_batch_refresh_ = false;
    }

    void init() {
        tables_ = std::make_unique<entities::TableRegistry>(source_);
        tables_->register_all(db_);
        functions::register_sql_functions(db_, *source_, [this]() {
            note_source_mutation();
        });
        register_cache_functions();
    }

    void note_source_mutation() {
        if (!tables_) {
            return;
        }
        if (in_batch_) {
            pending_batch_refresh_ = true;
            return;
        }
        invalidate_all_tables();
        update_last_seen_revision();
    }

    void register_cache_functions() {
        db_.register_function("cache_stats", 0, [this](xsql::FunctionContext& ctx, int, xsql::FunctionArg*) {
            xsql::json j;
            j["cache_invalidations_total"] = cache_invalidations_total_;
            j["last_seen_revision"] = last_seen_revision_;
            if (last_seen_token_) {
                j["last_seen_freshness_token"] = freshness_token_json(*last_seen_token_);
            }
            std::int64_t source_revision = 0;
            bool freshness_tracked = false;
            bool revision_tracked = false;
            SourceFreshnessToken source_token;
            if (source_ && source_->read_freshness_token(source_token)) {
                freshness_tracked = true;
                revision_tracked = true;
                source_revision = source_token.modification_number;
                j["source_freshness_token"] = freshness_token_json(source_token);
            } else {
                revision_tracked = source_ && source_->read_program_revision(source_revision);
            }
            if (!revision_tracked) {
                model::ProgramInfoRow info;
                if (source_ && source_->read_program_info(info)) {
                    source_revision = info.revision;
                }
            }
            j["source_revision"] = source_revision;
            j["revision_tracked"] = revision_tracked;
            j["freshness_tracked"] = freshness_tracked;
            j["schema_tables"] = {
                "project_files",
                "project_programs",
                "funcs",
                "segments",
                "memory_blocks",
                "memory_bytes",
                "names",
                "imports",
                "exports",
                "strings",
                "xrefs",
                "call_edges",
                "function_calls",
                "blocks",
                "cfg_edges",
                "loops",
                "switch_tables",
                "dominators",
                "post_dominators",
                "instructions",
                "comments",
                "data_items",
                "function_locals",
                "stack_vars",
                "register_vars",
                "function_chunks",
                "tail_calls",
                "program_options",
                "analysis_passes",
                "transactions",
                "project_properties",
                "relocations",
                "constants",
                "equates",
                "types",
                "type_members",
                "type_enums",
                "type_enum_members",
                "type_unions",
                "type_aliases",
                "signatures",
                "function_params",
                "function_frames",
                "text_index",
                "search_index",
                "xref_index",
                "function_metrics",
                "pseudocode",
                "decomp_lvars",
                "decomp_comments",
                "decomp_tokens",
                "breakpoints",
                "bookmarks",
                "sql_capabilities",
                "parity_findings",
                "perf_benchmarks",
                "live_meta",
                "db_info",
            };
            ctx.result_text(j.dump());
        });

        db_.register_function("cache_invalidate", 1, [this](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
            if (argc < 1 || argv[0].is_null()) {
                ctx.result_int(0);
                return;
            }
            if (!tables_) {
                ctx.result_int(0);
                return;
            }
            const std::string table = argv[0].as_text();
            const bool ok = tables_->invalidate_table(table);
            if (ok) {
                ++cache_invalidations_total_;
            }
            ctx.result_int(ok ? 1 : 0);
        });

        db_.register_function("cache_invalidate_all", 0, [this](xsql::FunctionContext& ctx, int, xsql::FunctionArg*) {
            if (!tables_) {
                ctx.result_int(0);
                return;
            }
            tables_->invalidate_all();
            ++cache_invalidations_total_;
            ctx.result_int(1);
        });
    }

    void refresh_if_needed() {
        if (!tables_ || !source_) {
            return;
        }
        SourceFreshnessToken token;
        if (source_->read_freshness_token(token)) {
            if (!last_seen_token_ || token != *last_seen_token_) {
                last_seen_token_ = token;
                last_seen_revision_ = token.modification_number;
                invalidate_all_tables();
            }
            return;
        }

        std::int64_t revision = 0;
        if (source_->read_program_revision(revision)) {
            last_seen_token_.reset();
            if (last_seen_revision_ == std::numeric_limits<std::int64_t>::min() ||
                revision != last_seen_revision_) {
                last_seen_revision_ = revision;
                invalidate_all_tables();
            }
            return;
        }

        model::ProgramInfoRow info;
        last_seen_token_.reset();
        last_seen_revision_ = source_->read_program_info(info) ? info.revision : 0;
        // Sources that do not opt into cheap freshness polling keep the old
        // conservative policy: every query starts from fresh table state.
        invalidate_all_tables();
    }

    void invalidate_all_tables() {
        if (!tables_) {
            return;
        }
        tables_->invalidate_all();
        ++cache_invalidations_total_;
    }

    void update_last_seen_revision() {
        if (!source_) {
            return;
        }
        SourceFreshnessToken token;
        if (source_->read_freshness_token(token)) {
            last_seen_token_ = token;
            last_seen_revision_ = token.modification_number;
            return;
        }
        last_seen_token_.reset();
        std::int64_t revision = 0;
        if (source_->read_program_revision(revision)) {
            last_seen_revision_ = revision;
            return;
        }
        model::ProgramInfoRow info;
        if (source_->read_program_info(info)) {
            last_seen_revision_ = info.revision;
        }
    }

    xsql::Database db_;
    std::shared_ptr<Source> source_;
    std::unique_ptr<entities::TableRegistry> tables_;
    std::string error_;
    std::optional<SourceFreshnessToken> last_seen_token_;
    std::int64_t last_seen_revision_ = std::numeric_limits<std::int64_t>::min();
    std::int64_t cache_invalidations_total_ = 0;
    int query_timeout_ms_ = 0;
    bool in_batch_ = false;
    bool pending_batch_refresh_ = false;
};

QueryEngine::QueryEngine(std::shared_ptr<Source> source)
    : impl_(std::make_unique<Impl>(std::move(source))) {}

QueryEngine::QueryEngine(QueryEngine&&) noexcept = default;
QueryEngine& QueryEngine::operator=(QueryEngine&&) noexcept = default;
QueryEngine::~QueryEngine() = default;

QueryResult QueryEngine::query(const std::string& sql) {
    return impl_->query(sql);
}

bool QueryEngine::execute(const std::string& sql) {
    return impl_->execute(sql);
}

bool QueryEngine::execute_script(
    const std::string& script,
    std::vector<QueryResult>& results,
    std::string& error)
{
    return impl_->execute_script(script, results, error);
}

std::string QueryEngine::scalar(const std::string& sql) {
    return impl_->scalar(sql);
}

std::vector<std::string> QueryEngine::list_tables() {
    return impl_->list_tables();
}

std::string QueryEngine::schema_for(const std::string& table) {
    return impl_->schema_for(table);
}

std::string QueryEngine::info() {
    return impl_->info();
}

bool QueryEngine::is_valid() const {
    return impl_->is_valid();
}

const std::string& QueryEngine::error() const {
    return impl_->error();
}

bool QueryEngine::refresh() {
    return impl_->refresh();
}

xsql::Database& QueryEngine::database() {
    return impl_->database();
}

const xsql::Database& QueryEngine::database() const {
    return impl_->database();
}

void QueryEngine::set_query_timeout_ms(int ms) {
    impl_->set_query_timeout_ms(ms);
}

int QueryEngine::query_timeout_ms() const {
    return impl_->query_timeout_ms();
}

std::unique_ptr<QueryEngine> create_libghidra_engine(const std::string& base_url,
                                                     const std::string& auth_token,
                                                     bool read_only,
                                                     int auto_save_interval) {
    LibGhidraSourceOptions options;
    options.base_url = base_url;
    options.auth_token = auth_token;
    options.read_only = read_only;
    options.auto_save_interval = auto_save_interval;
    return create_libghidra_engine(options);
}

std::unique_ptr<QueryEngine> create_libghidra_engine(const LibGhidraSourceOptions& options) {
    auto source = create_libghidra_live_source(options);
    if (!source) {
        return nullptr;
    }
    return std::make_unique<QueryEngine>(std::move(source));
}

std::unique_ptr<QueryEngine> create_callback_engine(SourceCallbacks callbacks) {
    auto source = create_callback_live_source(std::move(callbacks));
    return std::make_unique<QueryEngine>(std::move(source));
}

}  // namespace ghidrasql
