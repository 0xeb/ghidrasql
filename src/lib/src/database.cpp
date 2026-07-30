// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <ghidrasql/ghidrasql.hpp>
#include <ghidrasql/source.hpp>

#include "internal/entities.hpp"
#include "internal/functions.hpp"

#include <xsql/database.hpp>
#include <xsql/json.hpp>
#include <xsql/query_script.hpp>
#include <xsql/runtime_settings.hpp>
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
        // Shared runtime settings for this engine instance. ghidrasql historically
        // applied a per-query timeout only when it was explicitly > 0 (default 0 ==
        // "no timeout / use the transport default"); the shared core defaults
        // query_timeout_ms to 60000, so seed it back to 0 to preserve behavior.
        // The stack cap is stated explicitly (matches idasql/bnsql's 64).
        settings_ = std::make_shared<xsql::runtime::RuntimeSettingsCore>(
            xsql::runtime::RuntimeSettingsCoreOptions{64});
        settings_->set_query_timeout_ms(0);
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
        // Multi-statement input must run per-statement: sqlite3_prepare consumes
        // only the FIRST statement (silently dropping the rest), and the
        // single-pragma fast path below mis-parses a block that merely BEGINS with
        // `PRAGMA ghidrasql.*`. Split first; route a >1-statement block through the
        // shared per-statement path (execute_one_in_batch under a BatchScope -- the
        // same seam as execute_script()/run_script(), so pragma-leading and
        // pragma-interleaved blocks are handled statement-by-statement, each with
        // its own readonly detection + batch-refresh). Return the LAST statement's
        // result; abort on the first failure.
        std::vector<std::string> statements;
        std::string split_error;
        if (xsql::collect_statements(sql, statements, split_error) &&
            statements.size() > 1) {
            if (!db_.is_open()) {
                error_ = "database is not open";
                QueryResult result;
                result.error = error_;
                return result;
            }
            refresh_if_needed();
            BatchScope batch_scope(*this);
            QueryResult last;
            for (const auto& stmt : statements) {
                last = execute_one_in_batch(stmt);
                if (!last.success) {
                    error_ = last.error;
                    return last;
                }
            }
            if (pending_batch_refresh_) {
                flush_batch_refresh();
            }
            error_.clear();
            return last;
        }

        // Single-statement fast path: a lone runtime pragma handled directly, else
        // one prepared SQL statement.
        QueryResult pragma_result;
        if (try_handle_runtime_pragma(sql.c_str(), pragma_result)) {
            error_ = pragma_result.success ? "" : pragma_result.error;
            return pragma_result;
        }
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
            QueryResult result = execute_one_in_batch(stmt);
            results.push_back(result);
            if (!result.success) {
                error = result.error;
                return false;
            }
        }

        if (pending_batch_refresh_) {
            flush_batch_refresh();
        }

        error_.clear();
        return true;
    }

    // Canonical script path for HTTP /query and MCP. Runs the whole script under
    // one BatchScope with the same read-only/revision/cache-refresh logic as
    // execute_script() -- so a `UPDATE ...; SELECT ...` script never reads stale
    // cached data from the later statement -- while preserving ScriptOptions
    // (continue_on_error / include_sql) and the canonical envelope built by
    // xsql::run_script(). Per-statement work is shared with execute_script() via
    // execute_one_in_batch() so the two paths cannot drift.
    xsql::ScriptResult run_script(const std::string& script,
                                  const xsql::ScriptOptions& options)
    {
        if (!db_.is_open()) {
            xsql::ScriptResult out;
            out.success = false;
            out.parse_error = "database is not open";
            error_ = out.parse_error;
            return out;
        }
        refresh_if_needed();
        BatchScope batch_scope(*this);
        xsql::ScriptResult out = xsql::run_script(script, options,
            [this](const std::string& stmt, xsql::ScriptStatementResult& sr) {
                QueryResult r = execute_one_in_batch(stmt);
                sr.success = r.success;
                sr.error = r.error;
                sr.elapsed_ms = static_cast<double>(r.elapsed_ms);
                sr.columns = r.columns;
                sr.rows.reserve(r.rows.size());
                for (const auto& row : r.rows) {
                    sr.rows.push_back(row.values);
                }
            });
        if (pending_batch_refresh_) {
            flush_batch_refresh();
        }
        if (out.success) {
            error_.clear();
        }
        return out;
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
        // Read program info straight from the source (the binary table is
        // key/value rows now; the struct read avoids shape coupling).
        model::ProgramInfoRow row;
        if (!source_ || !source_->read_program_info(row)) {
            return "ghidrasql: no binary metadata available";
        }
        return "tool=" + row.tool_name +
               ", program=" + row.program_name +
               ", language=" + row.language_id +
               ", revision=" + std::to_string(row.revision);
    }

    bool is_valid() const { return db_.is_open(); }
    const std::string& error() const { return error_; }

    xsql::Database& database() { return db_; }
    const xsql::Database& database() const { return db_; }

    void set_query_timeout_ms(int ms) { settings_->set_query_timeout_ms(ms); }
    int query_timeout_ms() const { return settings_->query_timeout_ms(); }

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

    static QueryResult make_pragma_result(const std::string& key,
                                          const std::string& value) {
        QueryResult result;
        result.columns = {"name", "value"};
        Row row;
        row.values = {key, value};
        result.rows.push_back(std::move(row));
        result.success = true;
        return result;
    }

    static QueryResult make_pragma_error(const std::string& error) {
        QueryResult result;
        result.success = false;
        result.error = error;
        return result;
    }

    // Intercept `PRAGMA ghidrasql.*` runtime controls. Returns false (leaving
    // `out` untouched) when `sql` is not a ghidrasql runtime pragma so the caller
    // falls through to normal SQL execution. ghidrasql exposes only the 8 shared
    // keys (no tool-specific extras), so the shared dispatcher handles everything.
    bool try_handle_runtime_pragma(const char* sql, QueryResult& out) {
        const auto request = xsql::runtime::parse_runtime_pragma(sql, "ghidrasql");
        if (!request.matched) {
            return false;
        }
        // Clean break: only the two imperative timeout verbs remain PRAGMAs. Value
        // settings are read via SELECT and changed via UPDATE runtime_settings.
        if (request.key == "timeout_push" || request.key == "timeout_pop") {
            const auto common = xsql::runtime::handle_common_runtime_pragma(
                request, "ghidrasql", *settings_);
            // A successful timeout_push/pop changes the live values enumerated by
            // the `runtime_settings` table, so drop its cache. Sources that publish
            // an unchanged freshness token would otherwise serve a stale snapshot.
            if (common.success && tables_) {
                tables_->invalidate_table("runtime_settings");
            }
            out = common.success
                ? make_pragma_result(common.name, common.value)
                : make_pragma_error(common.error);
            return true;
        }
        out = make_pragma_error(
            xsql::runtime::unknown_runtime_pragma_error("ghidrasql"));
        return true;
    }

    QueryResult execute_sql(const std::string& sql) {
        QueryResult result;
        if (!db_.is_open()) {
            error_ = "database is not open";
            result.error = error_;
            return result;
        }

        xsql::Result raw;
        const int timeout_ms = settings_->query_timeout_ms();
        if (timeout_ms > 0) {
            xsql::QueryOptions opts;
            opts.timeout_ms = timeout_ms;
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
            if (!error.empty()) {
                return false;  // a genuine prepare error carrying its own message
            }
            // An invalid statement with NO message is ambiguous. SQLite prepares a
            // comment/whitespace-only fragment to a NULL statement -- a SUCCESSFUL
            // no-op -- and collect_statements() can hand us exactly that (a snippet
            // ending in a trailing "-- note" splits the note into its own
            // "statement"). That is NOT doc rot: the single-statement path runs such
            // a block cleanly, so the batch path must too. Other empty-message cases
            // are real prepare failures (e.g. unknown table) whose message
            // prepare_statement() dropped. Disambiguate with db_.query() -- which the
            // single-statement path uses and which no-ops a comment -- executing
            // nothing either way (a failed prepare has no side effect): if it
            // succeeds this is a readonly no-op; otherwise surface the real message.
            const auto rq = db_.query(sql);
            if (rq.ok()) {
                readonly = true;  // comment/whitespace no-op -- nothing to execute
                return true;
            }
            error = !rq.error.empty() ? rq.error : "statement failed to prepare";
            return false;
        }

        readonly = stmt.is_readonly();
        return true;
    }

    // Execute one statement inside an active BatchScope, applying read-only
    // detection, a pre-read cache flush, and post-mutation revision tracking.
    // This is the single per-statement path shared by execute_script() (vector
    // results) and run_script() (canonical envelope) so they cannot drift. A
    // prepare failure (e.g. unknown table) returns an unsuccessful QueryResult
    // carrying the error.
    QueryResult execute_one_in_batch(const std::string& stmt) {
        QueryResult result;

        // A `PRAGMA ghidrasql.*` statement is a runtime control, not SQL: it must
        // be handled before prepare (statement_is_readonly() would fail to prepare
        // it) so it works inside scripts / run_script() too. It never mutates the
        // source, so batch refresh/revision tracking is untouched.
        if (try_handle_runtime_pragma(stmt.c_str(), result)) {
            error_ = result.success ? "" : result.error;
            return result;
        }

        bool readonly = true;
        std::string ro_error;
        if (!statement_is_readonly(stmt, readonly, ro_error)) {
            error_ = ro_error;
            result.success = false;
            result.error = ro_error;
            return result;
        }
        if (pending_batch_refresh_ && readonly) {
            flush_batch_refresh();
        }

        auto token_before = current_freshness_token();
        const std::int64_t revision_before =
            token_before ? token_before->modification_number : current_revision();

        result = execute_sql(stmt);
        if (!result.success) {
            return result;
        }

        auto token_after = current_freshness_token();
        const bool source_changed = token_before && token_after
            ? *token_after != *token_before
            : current_revision() != revision_before;
        if (!readonly || source_changed) {
            pending_batch_refresh_ = true;
        }
        return result;
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
        tables_ = std::make_unique<entities::TableRegistry>(source_, settings_);
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
                "bytes",
                "byte_search",
                "names",
                "imports",
                "entries",
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
                "instruction_operands",
                "comments",
                "data_items",
                "function_locals",
                "stack_vars",
                "pcode_ops",
                "pcode_varnodes",
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
                "function_tags",
                "function_tag_mappings",
                "sql_capabilities",
                "parity_findings",
                "perf_benchmarks",
                "live_meta",
                "binary",
                "runtime_settings",
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
    std::shared_ptr<xsql::runtime::RuntimeSettingsCore> settings_;
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

xsql::ScriptResult QueryEngine::run_script(
    const std::string& script,
    const xsql::ScriptOptions& options)
{
    return impl_->run_script(script, options);
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
