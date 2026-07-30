// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <xsql/database.hpp>
#include <xsql/json.hpp>
#include <xsql/query_script.hpp>
#include <xsql/thinclient/http_query_server.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ghidrasql {

class Source;
struct SourceCallbacks;
struct LibGhidraSourceOptions;

struct Row {
    std::vector<std::string> values;

    const std::string& operator[](size_t i) const;
    size_t size() const;
};

struct QueryResult {
    std::vector<std::string> columns;
    std::vector<Row> rows;
    std::string error;
    bool success = false;
    bool timed_out = false;
    bool partial = false;
    int elapsed_ms = 0;

    size_t row_count() const;
    bool empty() const;
};

class QueryEngine {
public:
    explicit QueryEngine(std::shared_ptr<Source> source = nullptr);

    QueryEngine(const QueryEngine&) = delete;
    QueryEngine& operator=(const QueryEngine&) = delete;
    QueryEngine(QueryEngine&&) noexcept;
    QueryEngine& operator=(QueryEngine&&) noexcept;
    ~QueryEngine();

    QueryResult query(const std::string& sql);
    bool execute(const std::string& sql);
    bool execute_script(
        const std::string& script,
        std::vector<QueryResult>& results,
        std::string& error);
    // Canonical multi-statement path for HTTP /query and MCP: runs the whole
    // script under one batch with execute_script()'s read-only/revision/cache-
    // refresh semantics (no stale reads after a mid-script mutation) while
    // honoring ScriptOptions and returning the canonical envelope.
    xsql::ScriptResult run_script(
        const std::string& script,
        const xsql::ScriptOptions& options = {});
    std::string scalar(const std::string& sql);
    std::vector<std::string> list_tables();
    std::string schema_for(const std::string& table);
    std::string info();

    bool is_valid() const;
    const std::string& error() const;
    bool refresh();

    xsql::Database& database();
    const xsql::Database& database() const;

    void set_query_timeout_ms(int ms);
    int query_timeout_ms() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

std::unique_ptr<QueryEngine> create_libghidra_engine(
    const std::string& base_url,
    const std::string& auth_token = {},
    bool read_only = false,
    int auto_save_interval = 0);
std::unique_ptr<QueryEngine> create_libghidra_engine(const LibGhidraSourceOptions& options);
std::unique_ptr<QueryEngine> create_callback_engine(SourceCallbacks callbacks);

enum class CommandResult {
    NotHandled,
    Handled,
    Quit,
};

struct CommandCallbacks {
    std::function<std::string()> get_tables;
    std::function<std::string(const std::string&)> get_schema;
    std::function<std::string()> get_info;
    std::function<std::string()> save_database;
    std::function<std::string()> discard_changes;
    std::function<std::string()> refresh_database;

    std::function<std::string()> http_status;
    std::function<std::string()> http_start;
    std::function<std::string()> http_stop;
};

std::string trim(const std::string& input);

CommandResult handle_command(
    const std::string& input,
    const CommandCallbacks& callbacks,
    std::string& output);

xsql::json query_result_to_json(const QueryResult& result);

// Canonical script envelope used by every entry point (HTTP /query, CLI -q,
// MCP query tool). Single statement = array of one entry. See
// xsql::script_result_to_json() for the on-the-wire JSON shape:
//   { success, statement_count, results:[
//       { statement_index, success, columns, rows, row_count, elapsed_ms, error }
//     ], row_count_total, elapsed_ms_total, first_error_index, parse_error? }
//
// Fail-fast is the default; ScriptOptions::continue_on_error executes every
// statement regardless of earlier failures.
xsql::ScriptResult run_script(QueryEngine& engine,
                              const std::string& sql,
                              const xsql::ScriptOptions& options = {});

// Legacy wrapper around the canonical envelope kept for transitional callers
// that already hold a vector<QueryResult> from QueryEngine::execute_script.
// Emits the same xsql::script_result_to_json shape.
xsql::json script_results_to_json(
    const std::vector<QueryResult>& results,
    bool ok,
    const std::string& error);

class HttpServer {
public:
    struct Options {
        int port = 8081;
        std::string bind_address = "127.0.0.1";
        std::string auth_token;
        // /health/deep flips `healthy` to false when the oldest in-flight
        // query has been running longer than this threshold. /query latency
        // for cold decompiles is typically sub-second; values older than a
        // few seconds usually indicate a wedged worker. Set to 0 to make
        // /health/deep report only the observable state with no threshold.
        std::int64_t deep_health_threshold_ms = 5000;
        Options();
    };

    // Shutdown phase observable via /shutdown/status. Updated by:
    //   - HttpServer itself when /shutdown is hit (kIdle -> kHttpStopping).
    //   - The CLI orchestrator via set_shutdown_phase() at the lifecycle
    //     boundaries that HttpServer can't observe directly (kJavaExiting,
    //     kComplete, kForceKilled).
    enum class ShutdownPhase {
        kIdle = 0,
        kHttpStopping = 1,
        kJavaExiting = 2,
        kComplete = 3,
        kForceKilled = 4,
    };

    // Legacy callback: takes a SQL script and returns a JSON-string envelope.
    // Owns its own ScriptOptions, so it cannot honor request-supplied
    // continue_on_error / include_sql. Retained for callers/tests that don't
    // need server-side option parsing.
    using QueryFn = std::function<std::string(const std::string&)>;
    // Preferred callback: receives the raw script plus the options the HTTP
    // server parsed from the request (continue_on_error / include_sql) and runs
    // it through the engine's batch path (engine.run_script), returning the
    // canonical envelope. The server owns option parsing and output formatting.
    using ScriptFn =
        std::function<xsql::ScriptResult(const std::string&, const xsql::ScriptOptions&)>;
    using InfoFn = std::function<std::string()>;
    using RefreshFn = std::function<bool()>;
    using ProjectBodyFn = std::function<std::string(const std::string&)>;
    using ProjectInfoFn = std::function<std::string()>;

    struct ProjectControlFns {
        ProjectInfoFn list_programs;
        ProjectInfoFn active_program;
        ProjectBodyFn import_program;
        ProjectBodyFn open_program;
        ProjectBodyFn close_program;
    };

    HttpServer() = default;
    ~HttpServer();

    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;
    HttpServer(HttpServer&&) = delete;
    HttpServer& operator=(HttpServer&&) = delete;

    // Preferred: the server parses request options and hands the whole script
    // to script_fn (engine.run_script). Honors continue_on_error / include_sql.
    int start(
        ScriptFn script_fn,
        InfoFn info_fn,
        Options options = {},
        RefreshFn refresh_fn = {},
        ProjectControlFns project_fns = {});
    // Legacy overload: wires the JSON-string callback directly (no server-side
    // option parsing). Overload resolution selects this for 1-arg callbacks.
    int start(
        QueryFn query_fn,
        InfoFn info_fn,
        Options options = {},
        RefreshFn refresh_fn = {},
        ProjectControlFns project_fns = {});
    void stop();
    bool is_running() const;
    int port() const;
    std::string url() const;

    // Update the shutdown phase. The CLI orchestrator calls this at the
    // boundaries it controls (e.g. before/after headless->close()). The
    // HTTP /shutdown handler updates kHttpStopping itself when fired.
    void set_shutdown_phase(ShutdownPhase phase);

private:
    // Populate the shared server config (tool/help/bind/auth, status_fn, extra
    // routes) and stash the per-server callbacks. Both start() overloads call
    // this, then set their own executor, then launch().
    void configure_common(
        xsql::thinclient::http_query_server_config& cfg,
        InfoFn info_fn,
        Options options,
        RefreshFn refresh_fn,
        ProjectControlFns project_fns);
    // Construct and start the underlying server from a fully-populated config.
    // Returns the bound port, or 0 on failure.
    int launch(xsql::thinclient::http_query_server_config cfg);

    std::unique_ptr<xsql::thinclient::http_query_server> server_;
    InfoFn info_fn_;
    RefreshFn refresh_fn_;
    ProjectControlFns project_fns_;
    Options options_;

    // Worker state for /health/deep. The wrapper installed by start()
    // increments active_queries_ before delegating to the user's query_fn
    // and decrements after; latest_query_started_at_ms_ stamps every entry
    // so /health/deep can compute oldest_query_age_ms (precise for the
    // single-in-flight common case; reasonable for bursts).
    std::atomic<int> active_queries_{0};
    std::atomic<std::int64_t> latest_query_started_at_ms_{0};

    // Shutdown observability for /shutdown/status. The phase atomic is
    // stored as int (atomic<enum> isn't trivially constructible across
    // toolchains).
    std::atomic<int> shutdown_phase_{static_cast<int>(ShutdownPhase::kIdle)};
    std::atomic<std::int64_t> shutdown_initiated_at_ms_{0};
};

}  // namespace ghidrasql
