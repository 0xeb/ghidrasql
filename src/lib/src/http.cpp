// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

xsql::json script_results_to_json(
    const std::vector<QueryResult>& results,
    bool ok,
    const std::string& error)
{
    xsql::json j;
    j["success"] = ok;
    j["statement_count"] = results.size();

    auto array = xsql::json::array();
    std::size_t row_count_total = 0;
    for (const auto& result : results) {
        array.push_back(query_result_to_json(result));
        if (result.success) {
            row_count_total += result.rows.size();
        }
    }
    j["results"] = std::move(array);
    j["row_count_total"] = row_count_total;

    if (!ok) {
        j["error"] = error;
    }
    return j;
}

static std::string build_http_help_text() {
    return
        "GHIDRASQL HTTP REST API\n"
        "=======================\n\n"
        "SQL interface for Ghidra program databases via HTTP.\n\n"
        "Endpoints:\n"
        "  GET  /         - Welcome message\n"
        "  GET  /help     - This documentation\n"
        "  POST /query    - Execute SQL (body = raw SQL, multi-statement supported, response = JSON)\n"
        "  GET  /status   - Server status\n"
        "  POST /shutdown        - Stop server (async; returns immediately)\n"
        "  GET  /shutdown/status - Poll shutdown progress (phase: idle|http_stopping|java_exiting|complete|force_killed)\n"
        "  POST /refresh  - Refresh data from Ghidra\n"
        "  GET  /health   - Liveness probe (process up; does not probe the query worker)\n"
        "  GET  /health/deep - Readiness probe (reflects query-worker state)\n\n"
        "Discover Schema:\n"
        "  SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY type, name;\n\n"
        "Response Format:\n"
        "  Success: {\n"
        "    \"success\": true,\n"
        "    \"statement_count\": N,\n"
        "    \"row_count_total\": N,\n"
        "    \"results\": [\n"
        "      {\"success\": true, \"columns\": [...], \"rows\": [[...]], \"row_count\": N,\n"
        "       \"elapsed_ms\": N, \"partial\": false, \"timed_out\": false},\n"
        "      ...\n"
        "    ]\n"
        "  }\n"
        "  Failure: {\"success\": false, \"error\": \"message\", \"statement_count\": N, \"results\": [...]}\n"
        "  Single-statement bodies use the same shape with statement_count == 1.\n\n"
        "Example (single statement):\n"
        "  curl -X POST http://localhost:<port>/query -d \"SELECT name FROM funcs LIMIT 10\"\n"
        "Example (multi-statement):\n"
        "  curl -X POST http://localhost:<port>/query -d \"UPDATE funcs SET name='x' WHERE address=0x1000; SELECT save_database();\"\n";
}

HttpServer::~HttpServer() {
    stop();
}

int HttpServer::start(QueryFn query_fn, InfoFn info_fn, Options options, RefreshFn refresh_fn) {
    if (server_) {
        return server_->port();
    }

    options_ = std::move(options);
    info_fn_ = std::move(info_fn);
    refresh_fn_ = std::move(refresh_fn);

    // Reset worker-state counters so /health/deep starts from a clean slate
    // on each start() (matters across stop()/start() cycles in tests).
    active_queries_.store(0, std::memory_order_relaxed);
    latest_query_started_at_ms_.store(0, std::memory_order_relaxed);

    xsql::thinclient::http_query_server_config cfg;
    cfg.tool_name = "ghidrasql";
    cfg.help_text = build_http_help_text();
    cfg.port = options_.port;
    cfg.bind_address = options_.bind_address;
    cfg.auth_token = options_.auth_token;

    // Wrap the user-supplied query_fn so /health/deep can observe whether
    // a worker is currently busy and how long the oldest in-flight call has
    // been running. The wrapper does not change the response body; it only
    // brackets the call with two atomic updates.
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
        svr.Get("/health/deep", [this](const httplib::Request&, httplib::Response& res) {
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
        svr.Get("/shutdown/status", [this](const httplib::Request&, httplib::Response& res) {
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

        svr.Post("/refresh", [this](const httplib::Request&, httplib::Response& res) {
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
    };

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
