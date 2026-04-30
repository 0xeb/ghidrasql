// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <ghidrasql/ghidrasql.hpp>

namespace ghidrasql {

std::string trim(const std::string& input) {
    size_t a = input.find_first_not_of(" \t");
    if (a == std::string::npos) {
        return {};
    }
    size_t b = input.find_last_not_of(" \t");
    return input.substr(a, b - a + 1);
}

CommandResult handle_command(
    const std::string& input,
    const CommandCallbacks& callbacks,
    std::string& output)
{
    if (input.empty() || input[0] != '.') {
        return CommandResult::NotHandled;
    }

    if (input == ".quit" || input == ".exit" || input == ".q") {
        return CommandResult::Quit;
    }

    if (input == ".tables") {
        output = callbacks.get_tables ? callbacks.get_tables() : "";
        return CommandResult::Handled;
    }

    if (input == ".info") {
        output = callbacks.get_info ? callbacks.get_info() : "";
        return CommandResult::Handled;
    }

    if (input == ".save") {
        output = callbacks.save_database ? callbacks.save_database() : "save not supported";
        return CommandResult::Handled;
    }

    if (input == ".discard") {
        output = callbacks.discard_changes ? callbacks.discard_changes() : "discard not supported";
        return CommandResult::Handled;
    }

    if (input == ".refresh") {
        output = callbacks.refresh_database ? callbacks.refresh_database() : "refresh not supported";
        return CommandResult::Handled;
    }

    if (input.rfind(".schema", 0) == 0) {
        if (!callbacks.get_schema) {
            output = "schema callback not configured";
            return CommandResult::Handled;
        }
        std::string table = trim(input.substr(7));
        if (table.empty()) {
            output = "Usage: .schema <table>";
            return CommandResult::Handled;
        }
        output = callbacks.get_schema(table);
        return CommandResult::Handled;
    }

    if (input.rfind(".http", 0) == 0) {
        std::string arg = trim(input.substr(5));
        if (arg.empty()) {
            output = callbacks.http_status ? callbacks.http_status() : "http server unavailable";
            return CommandResult::Handled;
        }
        if (arg == "start") {
            output = callbacks.http_start ? callbacks.http_start() : "http server unavailable";
            return CommandResult::Handled;
        }
        if (arg == "stop") {
            output = callbacks.http_stop ? callbacks.http_stop() : "http server unavailable";
            return CommandResult::Handled;
        }
        if (arg == "help") {
            output =
                "HTTP Commands:\n"
                "  .http        show status\n"
                "  .http start  start server\n"
                "  .http stop   stop server\n";
            return CommandResult::Handled;
        }
    }

    if (input == ".help" || input == ".h") {
        output =
            "ghidrasql commands:\n"
            "  .tables           list all SQL tables and views\n"
            "  .schema <table>   show table or view schema\n"
            "  .info             show database metadata\n"
            "  .save             save pending changes (source-specific)\n"
            "  .discard          discard pending changes (source-specific)\n"
            "  .refresh          refresh source live readers and invalidate caches\n"
            "  .quit/.exit/.q    quit the REPL\n"
            "  .help             show this help\n"
            "  .http             show HTTP status\n"
            "  .http start       start HTTP server\n"
            "  .http stop        stop HTTP server\n"
            ;
        return CommandResult::Handled;
    }

    output = "Unknown command. Use .help";
    return CommandResult::Handled;
}

}  // namespace ghidrasql
