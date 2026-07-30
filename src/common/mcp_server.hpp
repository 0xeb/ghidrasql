// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

/**
 * mcp_server.hpp - MCP (Model Context Protocol) server wrapper for ghidrasql.
 *
 * Exposes one tool: `ghidrasql_query` — accepts a SQL string (single statement
 * or semicolon-separated script) and optional `continue_on_error` / `include_sql`
 * arguments. The response is the canonical xsql script envelope serialised as
 * the tool's text content.
 *
 * Modelled on idasql/src/common/mcp_server.hpp but simpler — ghidrasql has no
 * single-threaded host requirement so the callback is called directly from the
 * MCP server thread. Thread-safety is the caller's responsibility (e.g. by
 * locking around the supplied callback).
 */

#include <atomic>
#include <functional>
#include <memory>
#include <string>

namespace ghidrasql {

// SQL callback for handling MCP requests. Receives the raw script string and
// must return a JSON-encoded canonical envelope (e.g. via
// xsql::script_result_to_json(ghidrasql::run_script(engine, sql, options))).
using McpQueryCallback = std::function<std::string(const std::string& sql,
                                                   bool continue_on_error,
                                                   bool include_sql)>;

class GhidrasqlMcpServer {
public:
    GhidrasqlMcpServer();
    ~GhidrasqlMcpServer();

    GhidrasqlMcpServer(const GhidrasqlMcpServer&) = delete;
    GhidrasqlMcpServer& operator=(const GhidrasqlMcpServer&) = delete;

    // Start MCP server. port=0 lets the OS assign an ephemeral port (read the
    // real bound port back via port() after start()).
    // When auth_token is non-empty, the SSE transport enforces
    // `Authorization: Bearer <token>` on every request — matching the HTTP
    // server's --auth gate. Returns the actual bound port or -1 on failure.
    int start(int port, McpQueryCallback query_cb,
              const std::string& bind_addr = "127.0.0.1",
              const std::string& auth_token = "");

    void stop();
    bool is_running() const { return running_.load(); }
    int port() const { return port_; }
    const std::string& bind_addr() const { return bind_addr_; }
    std::string url() const;

private:
    std::atomic<bool> running_{false};
    std::string bind_addr_{"127.0.0.1"};
    std::string auth_token_;
    int port_{0};
    McpQueryCallback query_cb_;

    class Impl;
    std::unique_ptr<Impl> impl_;
};

// Formatting helper for CLI output: the MCP startup banner (SSE endpoint URL).
// ghidrasql's MCP is launch-flag-only (--mcp) with no REPL/health status-query
// surface, so a separate format_mcp_status() has no reachable caller — the
// running state is reported by this banner at start.
std::string format_mcp_info(int port, const std::string& bind_addr);

} // namespace ghidrasql
