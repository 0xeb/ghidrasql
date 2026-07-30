// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include "mcp_server.hpp"

#include <fastmcpp/mcp/handler.hpp>
#include <fastmcpp/server/sse_server.hpp>
#include <fastmcpp/tools/manager.hpp>
#include <fastmcpp/tools/tool.hpp>
#include <nlohmann/json.hpp>

#include <sstream>
#include <unordered_map>

namespace ghidrasql {

using Json = nlohmann::json;

class GhidrasqlMcpServer::Impl {
public:
    fastmcpp::tools::ToolManager tool_manager;
    std::unique_ptr<fastmcpp::server::SseServerWrapper> server;
};

GhidrasqlMcpServer::GhidrasqlMcpServer() = default;

GhidrasqlMcpServer::~GhidrasqlMcpServer() {
    stop();
}

int GhidrasqlMcpServer::start(int port, McpQueryCallback query_cb,
                              const std::string& bind_addr,
                              const std::string& auth_token)
{
    if (running_.load()) {
        return port_;
    }

    query_cb_ = std::move(query_cb);
    bind_addr_ = bind_addr;
    auth_token_ = auth_token;

    // port == 0 means "let the OS assign an ephemeral port": pass it straight
    // through to the SSE wrapper, which binds via bind_to_any_port and reports
    // the real bound port back through port() (read into port_ after start()).
    // Do NOT pre-pick a random port here — a random guess can collide with a
    // live socket, and the wrapper then wastes ~40s probing a port it never
    // bound. An OS-assigned port never collides.

    impl_ = std::make_unique<Impl>();

    Json query_input_schema = {
        {"type", "object"},
        {"properties", {
            {"query", {
                {"type", "string"},
                {"description",
                 "SQL query or semicolon-separated script to execute against the Ghidra database. "
                 "Single statement returns an array of one entry in the canonical envelope."}
            }},
            {"continue_on_error", {
                {"type", "boolean"},
                {"description",
                 "Run every statement regardless of earlier failures. Default: false (fail-fast)."}
            }},
            {"include_sql", {
                {"type", "boolean"},
                {"description",
                 "Echo each statement's SQL back in its results[].sql field."}
            }}
        }},
        {"required", Json::array({"query"})}
    };

    fastmcpp::tools::Tool sql_query_tool{
        "ghidrasql_query",
        query_input_schema,
        Json(),
        [this](const Json& args) -> Json {
            std::string query = args.value("query", "");
            if (query.empty()) {
                return Json{
                    {"content", Json::array({
                        Json{{"type", "text"}, {"text", "Error: missing query"}}
                    })},
                    {"isError", true}
                };
            }

            const bool continue_on_error = args.value("continue_on_error", false);
            const bool include_sql       = args.value("include_sql", false);

            if (!query_cb_) {
                return Json{
                    {"content", Json::array({
                        Json{{"type", "text"}, {"text", "Error: query callback not set"}}
                    })},
                    {"isError", true}
                };
            }

            std::string result;
            try {
                result = query_cb_(query, continue_on_error, include_sql);
            } catch (const std::exception& e) {
                result = std::string("Error: ") + e.what();
            }

            // The callback returns canonical-envelope JSON; we pass it
            // through as the tool's text content. The MCP client can parse
            // it. isError reflects the envelope's top-level success.
            bool is_error = false;
            try {
                auto j = Json::parse(result);
                if (j.is_object() && j.contains("success")
                        && j["success"].is_boolean()
                        && !j["success"].get<bool>()) {
                    is_error = true;
                }
            } catch (...) {
                // Non-JSON payload (shouldn't happen): treat as error if it
                // starts with "Error: ".
                if (result.rfind("Error: ", 0) == 0) {
                    is_error = true;
                }
            }

            return Json{
                {"content", Json::array({
                    Json{{"type", "text"}, {"text", result}}
                })},
                {"isError", is_error}
            };
        }
    };
    sql_query_tool.set_description(
        "Execute a SQL query or semicolon-separated script against the Ghidra "
        "database. Returns the canonical script envelope as JSON text.");
    impl_->tool_manager.register_tool(sql_query_tool);

    std::unordered_map<std::string, std::string> descriptions = {
        {"ghidrasql_query",
         "Execute a SQL query or semicolon-separated script against the Ghidra database."}
    };

    auto handler = fastmcpp::mcp::make_mcp_handler(
        "ghidrasql",
        "1.0.0",
        impl_->tool_manager,
        descriptions
    );

    impl_->server = std::make_unique<fastmcpp::server::SseServerWrapper>(
        handler,
        bind_addr_,
        port,
        "/sse",
        "/messages",
        auth_token_
    );

    running_.store(true);
    if (!impl_->server->start()) {
        running_.store(false);
        impl_.reset();
        return -1;
    }

    port_ = impl_->server->port();
    return port_;
}

void GhidrasqlMcpServer::stop() {
    running_.store(false);
    if (impl_ && impl_->server) {
        impl_->server->stop();
    }
    impl_.reset();
}

std::string GhidrasqlMcpServer::url() const {
    std::ostringstream ss;
    ss << "http://" << bind_addr_ << ":" << port_;
    return ss.str();
}

std::string format_mcp_info(int port, const std::string& bind_addr) {
    return "ghidrasql MCP server: http://" + bind_addr + ":"
           + std::to_string(port) + "/sse\n";
}

} // namespace ghidrasql
