// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <ghidrasql/ghidrasql.hpp>

#include <xsql/thinclient/http_query_server.hpp>

#include <chrono>
#include <thread>

namespace ghidrasql {

HttpServer::Options::Options() = default;

xsql::json query_result_to_json(const QueryResult& result) {
    xsql::json j;
    j["success"] = result.success;
    j["timed_out"] = result.timed_out;
    j["partial"] = result.partial;
    j["elapsed_ms"] = result.elapsed_ms;
    if (!result.success) {
        j["error"] = result.error;
        return j;
    }

    j["columns"] = result.columns;
    j["rows"] = xsql::json::array();
    for (const auto& row : result.rows) {
        j["rows"].push_back(row.values);
    }
    j["row_count"] = result.rows.size();
    return j;
}

namespace {

// Convert one ghidrasql::QueryResult into one xsql::ScriptStatementResult.
xsql::ScriptStatementResult to_script_stmt(const QueryResult& src, std::size_t idx) {
    xsql::ScriptStatementResult dst;
    dst.statement_index = idx;
    dst.success = src.success;
    dst.error = src.error;
    dst.elapsed_ms = static_cast<double>(src.elapsed_ms);
    dst.columns = src.columns;
    dst.rows.reserve(src.rows.size());
    for (const auto& row : src.rows) {
        dst.rows.push_back(row.values);
    }
    dst.row_count = dst.rows.size();
    return dst;
}

xsql::ScriptResult to_script_result(const std::vector<QueryResult>& results,
                                    bool ok,
                                    const std::string& error)
{
    xsql::ScriptResult out;
    out.success = ok;
    out.statement_count = results.size();
    out.results.reserve(results.size());
    for (std::size_t i = 0; i < results.size(); ++i) {
        auto stmt = to_script_stmt(results[i], i);
        if (!stmt.success && !out.first_error_index.has_value()) {
            out.first_error_index = i;
        }
        out.row_count_total += stmt.row_count;
        out.elapsed_ms_total += stmt.elapsed_ms;
        out.results.push_back(std::move(stmt));
    }
    // If execute_script reported a top-level error and no per-statement error
    // captured it (rare: splitter failure before any statement ran), surface it
    // via parse_error.
    if (!ok && !out.first_error_index.has_value() && !error.empty()) {
        out.parse_error = error;
    }
    return out;
}

// Bearer-token guard for custom routes. http_query_server enforces auth on its
// built-in routes (e.g. /query), but extra_routes handlers like /project/* run
// outside that check and would otherwise bypass --auth entirely. Mirrors the
// server's check_auth: an empty token means auth is disabled (open); otherwise
// require X-XSQL-Token or Authorization: Bearer <token>, and emit the same 401
// envelope on mismatch.
bool require_bearer(const httplib::Request& req, httplib::Response& res,
                    const std::string& auth_token) {
    if (auth_token.empty()) {
        return true;
    }
    std::string token;
    if (req.has_header("X-XSQL-Token")) {
        token = req.get_header_value("X-XSQL-Token");
    } else if (req.has_header("Authorization")) {
        const std::string auth = req.get_header_value("Authorization");
        const std::string prefix = "Bearer ";
        if (auth.rfind(prefix, 0) == 0) {
            token = auth.substr(prefix.size());
        }
    }
    if (token == auth_token) {
        return true;
    }
    res.status = 401;
    res.set_content(R"({"success":false,"error":"Unauthorized"})", "application/json");
    return false;
}

} // namespace

xsql::ScriptResult run_script(QueryEngine& engine,
                              const std::string& sql,
                              const xsql::ScriptOptions& options)
{
    // Delegate to the engine's batch-aware script path so HTTP/MCP scripts get
    // the same read-only/revision/cache-refresh semantics as execute_script()
    // (no stale reads after a mid-script mutation), with the canonical envelope.
    return engine.run_script(sql, options);
}

xsql::json script_results_to_json(
    const std::vector<QueryResult>& results,
    bool ok,
    const std::string& error)
{
    // Build canonical envelope and round-trip through xsql to get exact wire shape.
    auto script = to_script_result(results, ok, error);
    return xsql::json::parse(xsql::script_result_to_json(script));
}

static std::string build_http_help_text() {
    return
        "GHIDRASQL HTTP REST API\n"
        "=======================\n\n"
        "SQL interface for Ghidra program databases via HTTP.\n\n"
        "Endpoints:\n"
        "  GET  /         - Welcome message\n"
        "  GET  /help     - This documentation\n"
        "  POST /query    - Execute SQL (body = raw SQL, or JSON {sql,continue_on_error,include_sql}; multi-statement supported, response = JSON)\n"
        "  GET  /status   - Server status\n"
        "  POST /shutdown        - Stop server (async; returns immediately)\n"
        "  GET  /shutdown/status - Poll shutdown progress (phase: idle|http_stopping|java_exiting|complete|force_killed)\n"
        "  POST /refresh  - Refresh data from Ghidra\n"
        "  GET  /project/programs - List project programs when available\n"
        "  GET  /project/active   - Show the active project program\n"
        "  POST /project/import   - Import a binary into the project (JSON body)\n"
        "  POST /project/open     - Open a project program (JSON body)\n"
        "  POST /project/close    - Close the active program (JSON body)\n"
        "  GET  /health   - Liveness probe (process up; does not probe the query worker)\n"
        "  GET  /health/deep - Readiness probe (reflects query-worker state)\n\n"
        "Discover Schema:\n"
        "  SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY type, name;\n\n"
        "Response Format (canonical script envelope, single = array of one):\n"
        "  {\n"
        "    \"success\": true,\n"
        "    \"statement_count\": N,\n"
        "    \"results\": [\n"
        "      {\"statement_index\": 0, \"success\": true, \"columns\": [...], \"rows\": [[...]],\n"
        "       \"row_count\": N, \"elapsed_ms\": N, \"error\": null},\n"
        "      ...\n"
        "    ],\n"
        "    \"row_count_total\": N,\n"
        "    \"elapsed_ms_total\": N,\n"
        "    \"first_error_index\": null    // or index of earliest failed statement\n"
        "  }\n"
        "Splitter failure (e.g. unterminated quote): success:false, statement_count:0,\n"
        "  results:[], parse_error:\"<message>\".\n\n"
        "Options (query string or JSON body):\n"
        "  continue_on_error=1  - run every statement regardless of earlier failures\n"
        "  include_sql=1        - echo each statement's SQL back in its result\n\n"
        "Example (single statement):\n"
        "  curl -X POST http://localhost:<port>/query -d \"SELECT name FROM funcs LIMIT 10\"\n"
        "Example (multi-statement):\n"
        "  curl -X POST http://localhost:<port>/query -d \"UPDATE funcs SET name='x' WHERE addr=0x1000; SELECT save_database();\"\n";
}

HttpServer::~HttpServer() {
    stop();
}

int HttpServer::start(
    ScriptFn script_fn,
    InfoFn info_fn,
    Options options,
    RefreshFn refresh_fn,
    ProjectControlFns project_fns) {
    if (server_) {
        return server_->port();
    }

    xsql::thinclient::http_query_server_config cfg;
    configure_common(cfg, std::move(info_fn), std::move(options),
                     std::move(refresh_fn), std::move(project_fns));

    // Wrap the user-supplied script executor so /health/deep can observe whether
    // a worker is currently busy and how long the oldest in-flight call has
    // been running. The wrapper does not change the response body; it only
    // brackets the call with two atomic updates. Using script_executor (not
    // query_fn) lets the shared server parse continue_on_error / include_sql
    // from the request and hand them to engine.run_script.
    cfg.script_executor = [this, fn = std::move(script_fn)](
            const std::string& sql, const xsql::ScriptOptions& opts) -> xsql::ScriptResult {
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        latest_query_started_at_ms_.store(now_ms, std::memory_order_relaxed);
        active_queries_.fetch_add(1, std::memory_order_relaxed);
        struct CountGuard {
            std::atomic<int>* counter;
            ~CountGuard() { counter->fetch_sub(1, std::memory_order_relaxed); }
        } guard{&active_queries_};
        return fn(sql, opts);
    };

    return launch(std::move(cfg));
}

// Legacy JSON-string callback overload. Wires cfg.query_fn directly (the shared
// server returns the callback's JSON verbatim for format=json), preserving the
// pre-script_executor response shape for callers/tests that pass a 1-arg fn.
int HttpServer::start(
    QueryFn query_fn,
    InfoFn info_fn,
    Options options,
    RefreshFn refresh_fn,
    ProjectControlFns project_fns) {
    if (server_) {
        return server_->port();
    }

    xsql::thinclient::http_query_server_config cfg;
    configure_common(cfg, std::move(info_fn), std::move(options),
                     std::move(refresh_fn), std::move(project_fns));

    cfg.query_fn = [this, fn = std::move(query_fn)](const std::string& sql) -> std::string {
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        latest_query_started_at_ms_.store(now_ms, std::memory_order_relaxed);
        active_queries_.fetch_add(1, std::memory_order_relaxed);
        struct CountGuard {
            std::atomic<int>* counter;
            ~CountGuard() { counter->fetch_sub(1, std::memory_order_relaxed); }
        } guard{&active_queries_};
        return fn(sql);
    };

    return launch(std::move(cfg));
}

void HttpServer::configure_common(
    xsql::thinclient::http_query_server_config& cfg,
    InfoFn info_fn,
    Options options,
    RefreshFn refresh_fn,
    ProjectControlFns project_fns) {
    options_ = std::move(options);
    info_fn_ = std::move(info_fn);
    refresh_fn_ = std::move(refresh_fn);
    project_fns_ = std::move(project_fns);

    // Reset worker-state counters so /health/deep starts from a clean slate
    // on each start() (matters across stop()/start() cycles in tests).
    active_queries_.store(0, std::memory_order_relaxed);
    latest_query_started_at_ms_.store(0, std::memory_order_relaxed);

    cfg.tool_name = "ghidrasql";
    cfg.help_text = build_http_help_text();
    cfg.port = options_.port;
    cfg.bind_address = options_.bind_address;
    cfg.auth_token = options_.auth_token;
    // /status carries readiness DATA (running/port/info) here, and ghidrasql exposes a
    // separate public /health liveness probe, so /status stays bearer-guarded (unlike
    // the shared server's default of a public /status liveness probe).
    cfg.status_requires_auth = true;

    cfg.status_fn = [this]() -> xsql::json {
        xsql::json extra;
        extra["running"] = is_running();
        extra["port"] = port();
        if (info_fn_) {
            extra["info"] = info_fn_();
        }
        return extra;
    };

    cfg.extra_routes = [this](httplib::Server& svr) {
        svr.Get("/health", [this](const httplib::Request&, httplib::Response& res) {
            xsql::json status = {
                {"success", true},
                {"status", "ok"},
                {"tool", "ghidrasql"},
            };
            res.set_content(status.dump(), "application/json");
        });

        // /health/deep — readiness probe that reflects the query worker.
        // Returns:
        //   healthy: false   when an in-flight query has exceeded the
        //                    deep_health_threshold_ms window (suspect wedge).
        //   healthy: true    otherwise (no in-flight query, or in-flight
        //                    but within the threshold).
        // Always reports observable state: active_queries, oldest_query_age_ms.
        svr.Get("/health/deep", [this](const httplib::Request& req, httplib::Response& res) {
            // Exposes worker internals (active queries, ages) -> require auth.
            // /health stays public as the unauthenticated liveness probe.
            if (!require_bearer(req, res, options_.auth_token)) return;
            const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            const int active = active_queries_.load(std::memory_order_relaxed);
            const auto started = latest_query_started_at_ms_.load(std::memory_order_relaxed);
            const std::int64_t age_ms = (active > 0 && started > 0) ? (now_ms - started) : 0;

            const std::int64_t threshold = options_.deep_health_threshold_ms;
            bool healthy = true;
            std::string reason;
            if (active > 0 && threshold > 0 && age_ms > threshold) {
                healthy = false;
                reason = "query_worker_busy";
            }

            xsql::json status;
            status["healthy"] = healthy;
            status["tool"] = "ghidrasql";
            status["active_queries"] = active;
            status["oldest_query_age_ms"] = age_ms;
            status["threshold_ms"] = threshold;
            if (!healthy) {
                status["reason"] = reason;
                res.status = 503;
            }
            res.set_content(status.dump(), "application/json");
        });

        // /shutdown/status — observability for the shutdown lifecycle.
        // The /shutdown handler returns success immediately and triggers an
        // async stop, but the wrapper's headless->close() can take seconds
        // to many seconds depending on Java state. Operators polling this
        // endpoint can distinguish "still running normally" from "in flight"
        // from "complete / force-killed".
        svr.Get("/shutdown/status", [this](const httplib::Request& req, httplib::Response& res) {
            // Control-plane lifecycle detail -> require auth (like /shutdown).
            if (!require_bearer(req, res, options_.auth_token)) return;
            const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            const int phase = shutdown_phase_.load(std::memory_order_relaxed);
            const auto initiated_at = shutdown_initiated_at_ms_.load(std::memory_order_relaxed);
            const auto initiated = (initiated_at != 0);
            const auto age_ms = (initiated && initiated_at > 0) ? (now_ms - initiated_at) : 0;

            const char* phase_name = "idle";
            switch (static_cast<ShutdownPhase>(phase)) {
                case ShutdownPhase::kIdle:         phase_name = "idle"; break;
                case ShutdownPhase::kHttpStopping: phase_name = "http_stopping"; break;
                case ShutdownPhase::kJavaExiting:  phase_name = "java_exiting"; break;
                case ShutdownPhase::kComplete:     phase_name = "complete"; break;
                case ShutdownPhase::kForceKilled:  phase_name = "force_killed"; break;
            }

            xsql::json status;
            status["tool"] = "ghidrasql";
            status["phase"] = phase_name;
            status["initiated"] = initiated;
            status["age_ms"] = age_ms;
            status["listener_running"] = is_running();
            res.set_content(status.dump(), "application/json");
        });

        svr.Post("/refresh", [this](const httplib::Request& req, httplib::Response& res) {
            // Mutates server state (re-reads the program) -> require auth.
            if (!require_bearer(req, res, options_.auth_token)) return;
            if (!refresh_fn_) {
                res.status = 501;
                res.set_content(
                    xsql::json{{"success", false}, {"error", "refresh callback not configured"}}.dump(),
                    "application/json");
                return;
            }
            bool ok = refresh_fn_();
            if (!ok) {
                res.status = 500;
                res.set_content(
                    xsql::json{{"success", false}, {"error", "refresh failed"}}.dump(),
                    "application/json");
                return;
            }
            res.set_content(
                xsql::json{{"success", true}, {"message", "refreshed"}}.dump(),
                "application/json");
        });

        svr.Get("/project/programs", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_bearer(req, res, options_.auth_token)) return;
            if (!project_fns_.list_programs) {
                res.status = 501;
                res.set_content(
                    xsql::json{{"success", false}, {"error", "project control not configured"}}.dump(),
                    "application/json");
                return;
            }
            res.set_content(project_fns_.list_programs(), "application/json");
        });

        svr.Get("/project/active", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_bearer(req, res, options_.auth_token)) return;
            if (!project_fns_.active_program) {
                res.status = 501;
                res.set_content(
                    xsql::json{{"success", false}, {"error", "project control not configured"}}.dump(),
                    "application/json");
                return;
            }
            res.set_content(project_fns_.active_program(), "application/json");
        });

        svr.Post("/project/import", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_bearer(req, res, options_.auth_token)) return;
            if (!project_fns_.import_program) {
                res.status = 501;
                res.set_content(
                    xsql::json{{"success", false}, {"error", "project control not configured"}}.dump(),
                    "application/json");
                return;
            }
            res.set_content(project_fns_.import_program(req.body), "application/json");
        });

        svr.Post("/project/open", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_bearer(req, res, options_.auth_token)) return;
            if (!project_fns_.open_program) {
                res.status = 501;
                res.set_content(
                    xsql::json{{"success", false}, {"error", "project control not configured"}}.dump(),
                    "application/json");
                return;
            }
            res.set_content(project_fns_.open_program(req.body), "application/json");
        });

        svr.Post("/project/close", [this](const httplib::Request& req, httplib::Response& res) {
            if (!require_bearer(req, res, options_.auth_token)) return;
            if (!project_fns_.close_program) {
                res.status = 501;
                res.set_content(
                    xsql::json{{"success", false}, {"error", "project control not configured"}}.dump(),
                    "application/json");
                return;
            }
            res.set_content(project_fns_.close_program(req.body), "application/json");
        });
    };
}

int HttpServer::launch(xsql::thinclient::http_query_server_config cfg) {
    server_ = std::make_unique<xsql::thinclient::http_query_server>(cfg);
    int started_port = server_->start();
    if (started_port < 0) {
        server_.reset();
        return 0;
    }
    return started_port;
}

void HttpServer::stop() {
    if (!server_) {
        return;
    }
    if (server_->is_running()) {
        // No /shutdown in flight; safe to stop directly.
        server_->stop();
    } else {
        // The /shutdown endpoint spawns a detached thread that calls
        // http_query_server::stop() after a 100ms sleep.  That method is NOT
        // thread-safe (httplib asserts on double svr_->stop()), so we must
        // not call it concurrently.  running_ is already false (set at the
        // start of stop()), but httplib socket closure and server thread join
        // may still be in progress.  Wait for the detached thread to finish.
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    server_.reset();
}

bool HttpServer::is_running() const {
    return server_ && server_->is_running();
}

int HttpServer::port() const {
    return server_ ? server_->port() : 0;
}

std::string HttpServer::url() const {
    if (!server_) {
        return {};
    }
    return server_->url();
}

void HttpServer::set_shutdown_phase(ShutdownPhase phase) {
    shutdown_phase_.store(static_cast<int>(phase), std::memory_order_relaxed);
}

}  // namespace ghidrasql
