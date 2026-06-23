// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <ghidrasql/ghidrasql.hpp>
#include <ghidrasql/source.hpp>

#include <xsql/script.hpp>
#ifdef GHIDRASQL_HAS_LIBGHIDRA
#include <libghidra/headless.hpp>
#include <libghidra/http.hpp>
#endif

#ifdef _WIN32
#include <io.h>
#define STDIN_IS_TTY() (_isatty(_fileno(stdin)))
#else
#include <unistd.h>
#define STDIN_IS_TTY() (isatty(fileno(stdin)))
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<bool> g_stop{false};

void signal_handler(int) {
    g_stop.store(true);
}

struct Args {
    std::string query;
    std::string sql_file;
    bool interactive = false;
    bool serve = false;
    int port = 8081;
    std::string bind = "127.0.0.1";
    std::string auth_token;

    // Connection (pick one)
    std::string url;       // --url <url>   → connect mode
    std::string ghidra;    // --ghidra <path> → headless mode

    // Program/project (shared)
    std::string binary_path;
    std::vector<std::string> binary_paths;
    std::string program;
    std::vector<std::string> programs;
    std::string initial_program;
    bool list_project_programs = false;
    std::string project;
    std::string project_name;
    bool analyze = true;        // default: analyze in headless
    bool analyze_explicit = false;
    bool readonly = false;
    bool fresh = false;

    // Lifecycle (headless)
    std::string shutdown;       // save|discard|none
    bool shutdown_explicit = false;
    bool keep_host = false;
    int max_runtime = 600;

    int rpc_port = 18080;
    int auto_save_interval = 0;
    int rpc_timeout_ms = 0;  // 0 = use libghidra default (120s)

    std::string format;

    // Pass-through args for analyzeHeadless (everything after '--')
    std::vector<std::string> extra_headless_args;

    bool help = false;
    bool version = false;
};

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool is_one_of(const std::string& value, std::initializer_list<const char*> allowed) {
    for (const char* item : allowed) {
        if (value == item) {
            return true;
        }
    }
    return false;
}

std::string normalize_project_program_arg(std::string value) {
    std::replace(value.begin(), value.end(), '\\', '/');
    if (value.empty()) {
        return value;
    }
    if (value.front() == '/') {
        return value;
    }
    if (value.find('/') != std::string::npos) {
        return "/" + value;
    }
    return value;
}

std::string selected_program_arg(const Args& args) {
    if (!args.initial_program.empty()) {
        return normalize_project_program_arg(args.initial_program);
    }
    if (!args.programs.empty()) {
        return normalize_project_program_arg(args.programs.front());
    }
    return {};
}

// Map removed flags to their replacements for helpful error messages.
struct FlagReplacement {
    const char* old_flag;
    const char* message;
};

const FlagReplacement kRemovedFlags[] = {
    {"--headless-live-host",    "mode is auto-detected: use --ghidra <path> for headless mode"},
    {"--ghidra-root",           "use --ghidra <path> instead"},
    {"--headless-analyze",      "use --analyze or --no-analyze instead"},
    {"--headless-project-mode", "use --fresh instead of --headless-project-mode fresh"},
    {"--headless-script-path",  "removed; the script is found automatically in the Ghidra distribution's extensions"},
    {"--headless-shutdown",     "use --shutdown <mode> instead"},
    {"--host-max-runtime-sec",  "use --max-runtime <sec> instead"},
    {"--project-dir",           "use --project <dir> instead"},
    {"--program-path",          "use --program <name> instead"},
    {"--summary-json",          "removed; snapshot/export ingestion is no longer supported"},
    {"--headless-summary",      "removed; snapshot/export ingestion is no longer supported"},
    {"--ghidra-api-url",        "use --url <url> instead"},
};

void print_help() {
    std::cout
        << "ghidrasql - SQL interface for Ghidra analysis data\n\n"
        << "Usage:\n"
        << "  ghidrasql --ghidra <path> --binary target.exe --project ./proj --project-name demo -q \"SELECT * FROM funcs LIMIT 5\"\n"
        << "  ghidrasql --url http://127.0.0.1:18080 -q \"SELECT name FROM funcs LIMIT 5\"\n"
        << "  ghidrasql --url http://127.0.0.1:18080 -i\n"
        << "  ghidrasql --ghidra <path> --binary target.exe --project ./proj --project-name demo --http\n\n"
        << "Connection (pick one):\n"
        << "  --ghidra <path>            Ghidra distribution path (headless mode)\n"
        << "                             Falls back to GHIDRA_INSTALL_DIR env var\n"
        << "  --url <url>                Connect to running LibGhidraHost\n\n"
        << "Actions:\n"
        << "  -q, --query <sql>          Execute query and exit\n"
        << "  -f, --file <path>          Execute SQL script and exit\n"
        << "  -i, --interactive          Interactive REPL (default when no action)\n"
        << "  --http                     Start HTTP API server\n"
        << "  --list-project-programs    List programs in the current/opened project and exit\n"
        << "  --format <fmt>             Output format: table (default) or json\n\n"
        << "Program/project:\n"
        << "  --binary <path>            Binary to import (headless only; repeatable)\n"
        << "  --program <name>           Existing program in project (repeatable)\n"
        << "  --initial-program <name>   Project program to make active in this host\n"
        << "  --project <dir>            Project directory\n"
        << "  --project-name <name>      Project name\n"
        << "  --analyze                  Run analysis (default in headless)\n"
        << "  --no-analyze               Skip analysis\n"
        << "  --readonly                 Read-only session\n\n"
        << "Server/network:\n"
        << "  --port <n>                 HTTP port (default: 8081)\n"
        << "  --bind <addr>              Bind address (default: 127.0.0.1)\n"
        << "  --auth <token>             Bearer auth token\n\n"
        << "Lifecycle (headless):\n"
        << "  --shutdown <mode>          save|discard|none (default: save; discard when --readonly)\n"
        << "  --keep-host                Don't auto-shutdown after query\n"
        << "  --max-runtime <sec>        Host lifetime bound (default: 600, 0=disable)\n"
        << "  --rpc-port <n>             LibGhidraHost RPC port (headless only, default: 18080)\n"
        << "  --rpc-timeout-ms <n>       Per-RPC read timeout (0=libghidra default 120000)\n"
        << "  --fresh                    Delete existing project first\n"
        << "  --auto-save <n>            Save every N mutations (0=disabled, default)\n\n"
        << "Meta:\n"
        << "  -h, --help                 Show this help\n"
        << "  --version                  Show version\n";
}

bool parse_args(int argc, char** argv, Args& args) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--") {
            // Everything after '--' is passed verbatim to analyzeHeadless.
            for (int j = i + 1; j < argc; ++j)
                args.extra_headless_args.emplace_back(argv[j]);
            break;
        }
        if (arg == "-h" || arg == "--help") {
            args.help = true;
        } else if (arg == "--version") {
            args.version = true;
        } else if (arg == "-q" || arg == "--query") {
            if (++i >= argc) {
                std::cerr << "missing value for " << arg << "\n";
                return false;
            }
            args.query = argv[i];
        } else if (arg == "-f" || arg == "--file") {
            if (++i >= argc) {
                std::cerr << "missing value for " << arg << "\n";
                return false;
            }
            args.sql_file = argv[i];
        } else if (arg == "-i" || arg == "--interactive") {
            args.interactive = true;
        } else if (arg == "--http" || arg == "--serve") {
            args.serve = true;
        } else if (arg == "--list-project-programs") {
            args.list_project_programs = true;
        } else if (arg == "--port") {
            if (++i >= argc) {
                std::cerr << "missing value for --port\n";
                return false;
            }
            try {
                args.port = std::stoi(argv[i]);
            } catch (...) {
                std::cerr << "invalid value for --port: " << argv[i] << "\n";
                return false;
            }
        } else if (arg == "--rpc-port") {
            if (++i >= argc) {
                std::cerr << "missing value for --rpc-port\n";
                return false;
            }
            try {
                args.rpc_port = std::stoi(argv[i]);
            } catch (...) {
                std::cerr << "invalid value for --rpc-port: " << argv[i] << "\n";
                return false;
            }
        } else if (arg == "--rpc-timeout-ms") {
            if (++i >= argc) {
                std::cerr << "missing value for --rpc-timeout-ms\n";
                return false;
            }
            try {
                args.rpc_timeout_ms = std::stoi(argv[i]);
            } catch (...) {
                std::cerr << "invalid value for --rpc-timeout-ms: " << argv[i] << "\n";
                return false;
            }
            if (args.rpc_timeout_ms < 0) {
                std::cerr << "invalid --rpc-timeout-ms (must be >= 0): " << args.rpc_timeout_ms << "\n";
                return false;
            }
        } else if (arg == "--bind") {
            if (++i >= argc) {
                std::cerr << "missing value for --bind\n";
                return false;
            }
            args.bind = argv[i];
        } else if (arg == "--auth") {
            if (++i >= argc) {
                std::cerr << "missing value for --auth\n";
                return false;
            }
            args.auth_token = argv[i];
        } else if (arg == "--ghidra") {
            if (++i >= argc) {
                std::cerr << "missing value for --ghidra\n";
                return false;
            }
            args.ghidra = argv[i];
        } else if (arg == "--url") {
            if (++i >= argc) {
                std::cerr << "missing value for --url\n";
                return false;
            }
            args.url = argv[i];
        } else if (arg == "--binary") {
            if (++i >= argc) {
                std::cerr << "missing value for --binary\n";
                return false;
            }
            args.binary_path = argv[i];
            args.binary_paths.emplace_back(argv[i]);
        } else if (arg == "--program") {
            if (++i >= argc) {
                std::cerr << "missing value for --program\n";
                return false;
            }
            args.program = argv[i];
            args.programs.emplace_back(argv[i]);
        } else if (arg == "--initial-program") {
            if (++i >= argc) {
                std::cerr << "missing value for --initial-program\n";
                return false;
            }
            args.initial_program = argv[i];
        } else if (arg == "--project") {
            if (++i >= argc) {
                std::cerr << "missing value for --project\n";
                return false;
            }
            args.project = argv[i];
        } else if (arg == "--project-name") {
            if (++i >= argc) {
                std::cerr << "missing value for --project-name\n";
                return false;
            }
            args.project_name = argv[i];
        } else if (arg == "--analyze") {
            args.analyze = true;
            args.analyze_explicit = true;
        } else if (arg == "--no-analyze") {
            args.analyze = false;
            args.analyze_explicit = true;
        } else if (arg == "--readonly") {
            args.readonly = true;
        } else if (arg == "--fresh") {
            args.fresh = true;
        } else if (arg == "--shutdown") {
            if (++i >= argc) {
                std::cerr << "missing value for --shutdown\n";
                return false;
            }
            args.shutdown = argv[i];
            args.shutdown_explicit = true;
        } else if (arg == "--keep-host") {
            args.keep_host = true;
        } else if (arg == "--max-runtime") {
            if (++i >= argc) {
                std::cerr << "missing value for --max-runtime\n";
                return false;
            }
            try {
                args.max_runtime = std::stoi(argv[i]);
            } catch (...) {
                std::cerr << "invalid value for --max-runtime: " << argv[i] << "\n";
                return false;
            }
        } else if (arg == "--auto-save") {
            if (++i >= argc) {
                std::cerr << "missing value for --auto-save\n";
                return false;
            }
            try {
                args.auto_save_interval = std::stoi(argv[i]);
            } catch (...) {
                std::cerr << "invalid value for --auto-save: " << argv[i] << "\n";
                return false;
            }
        } else if (arg == "--format") {
            if (++i >= argc) {
                std::cerr << "missing value for --format\n";
                return false;
            }
            args.format = to_lower(argv[i]);
            if (!is_one_of(args.format, {"table", "json"})) {
                std::cerr << "invalid --format value: " << argv[i]
                          << " (expected table|json)\n";
                return false;
            }
        } else {
            // Check if this is a removed flag with a helpful replacement message
            for (const auto& removed : kRemovedFlags) {
                if (arg == removed.old_flag) {
                    std::cerr << "unknown option: " << arg << "\n";
                    std::cerr << "  " << removed.message << "\n";
                    return false;
                }
            }
            std::cerr << "unknown option: " << arg << "\n";
            return false;
        }
    }
    return true;
}

bool validate_headless_args(Args& args) {
    bool ok = true;
    auto require_value = [&](const std::string& value, const std::string& name) {
        if (!value.empty()) {
            return;
        }
        std::cerr << "missing required option for headless mode: " << name << "\n";
        ok = false;
    };

    require_value(args.project, "--project");
    require_value(args.project_name, "--project-name");

    const bool has_seed =
        !args.binary_paths.empty() || !args.programs.empty() || !args.initial_program.empty();
    if (!has_seed) {
        std::cerr
            << "headless mode requires at least one of --binary, --program, "
            << "or --initial-program\n";
        ok = false;
    }

    if (!args.shutdown_explicit) {
        args.shutdown = args.readonly ? "discard" : "save";
    }
    args.shutdown = to_lower(args.shutdown);

    if (!is_one_of(args.shutdown, {"save", "discard", "none"})) {
        std::cerr << "invalid --shutdown value: " << args.shutdown << " (expected save|discard|none)\n";
        ok = false;
    }
    if (args.readonly && args.shutdown != "discard") {
        std::cerr << "--readonly requires --shutdown discard (or omit --shutdown)\n";
        ok = false;
    }
    if (args.port <= 0 || args.port > 65535) {
        std::cerr << "invalid --port value: " << args.port << "\n";
        ok = false;
    }
    if (args.rpc_port <= 0 || args.rpc_port > 65535) {
        std::cerr << "invalid --rpc-port value: " << args.rpc_port << "\n";
        ok = false;
    }
    if (args.max_runtime < 0) {
        std::cerr << "invalid --max-runtime value: " << args.max_runtime
                  << " (expected >= 0)\n";
        ok = false;
    }
    return ok;
}

void maybe_delete_project(const Args& args) {
    if (!args.fresh) {
        return;
    }

    namespace fs = std::filesystem;
    fs::path project_dir(args.project);
    fs::path gpr = project_dir / (args.project_name + ".gpr");
    fs::path rep = project_dir / (args.project_name + ".rep");

    std::error_code ec;
    if (fs::exists(gpr, ec)) {
        fs::remove_all(gpr, ec);
    }
    ec.clear();
    if (fs::exists(rep, ec)) {
        fs::remove_all(rep, ec);
    }
}

void print_result(const ghidrasql::QueryResult& result, const std::string& format = "") {
    if (format == "json") {
        std::cout << ghidrasql::query_result_to_json(result).dump() << "\n";
        return;
    }

    if (!result.success) {
        std::cerr << "error: " << result.error << "\n";
        return;
    }
    if (result.columns.empty()) {
        std::cout << "ok\n";
        return;
    }

    std::vector<size_t> widths(result.columns.size(), 0);
    for (size_t i = 0; i < result.columns.size(); ++i) {
        widths[i] = result.columns[i].size();
    }
    for (const auto& row : result.rows) {
        for (size_t i = 0; i < row.values.size(); ++i) {
            widths[i] = std::max(widths[i], row.values[i].size());
        }
    }

    auto print_sep = [&]() {
        std::cout << "+";
        for (size_t w : widths) {
            std::cout << std::string(w + 2, '-') << "+";
        }
        std::cout << "\n";
    };

    print_sep();
    std::cout << "|";
    for (size_t i = 0; i < result.columns.size(); ++i) {
        std::cout << " " << std::left << std::setw(static_cast<int>(widths[i])) << result.columns[i] << " |";
    }
    std::cout << "\n";
    print_sep();

    for (const auto& row : result.rows) {
        std::cout << "|";
        for (size_t i = 0; i < widths.size(); ++i) {
            const std::string value = i < row.values.size() ? row.values[i] : "";
            std::cout << " " << std::left << std::setw(static_cast<int>(widths[i])) << value << " |";
        }
        std::cout << "\n";
    }
    print_sep();
    std::cout << result.rows.size() << " row(s)\n";
}

std::string join_lines(const std::vector<std::string>& lines) {
    std::ostringstream out;
    for (size_t i = 0; i < lines.size(); ++i) {
        out << lines[i];
        if (i + 1 < lines.size()) {
            out << "\n";
        }
    }
    return out.str();
}

int run_script(ghidrasql::QueryEngine& engine, const std::string& path, const std::string& format = "") {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "cannot open script: " << path << "\n";
        return 1;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    std::vector<ghidrasql::QueryResult> results;
    std::string error;
    if (!engine.execute_script(content, results, error)) {
        if (!results.empty()) {
            for (const auto& result : results) {
                print_result(result, format);
            }
        }
        std::cerr << "error: " << error << "\n";
        return 1;
    }

    for (const auto& result : results) {
        print_result(result, format);
    }
    return 0;
}

int print_project_programs(ghidrasql::QueryEngine& engine, const std::string& format = "") {
    auto result = engine.query(
        "SELECT path, name, folder_path, content_type, domain_object_class "
        "FROM project_programs ORDER BY path");
    print_result(result, format);
    return result.success ? 0 : 1;
}

int run_repl(
    ghidrasql::QueryEngine& engine,
    std::shared_ptr<ghidrasql::Source> source,
    ghidrasql::HttpServer& http,
    const ghidrasql::HttpServer::Options& http_options,
    const std::string& format)
{
    const bool is_tty = STDIN_IS_TTY();

    auto http_start = [&]() -> std::string {
        if (http.is_running()) {
            return "HTTP already running at " + http.url();
        }
        int port = http.start(
            [&](const std::string& sql, xsql::ScriptStatementResult& out) {
                const ghidrasql::QueryResult r = engine.query(sql);
                out.columns = r.columns;
                out.rows.reserve(r.rows.size());
                for (const auto& row : r.rows) out.rows.push_back(row.values);
                out.success = r.success;
                out.error = r.error;
                out.elapsed_ms = r.elapsed_ms;
            },
            [&]() { return engine.info(); },
            http_options,
            [&]() { return engine.refresh(); });
        if (port <= 0) {
            return "failed to start HTTP server";
        }
        return "HTTP started at " + http.url();
    };

    auto http_stop = [&]() -> std::string {
        if (!http.is_running()) {
            return "HTTP is not running";
        }
        http.stop();
        return "HTTP stopped";
    };

    auto http_status = [&]() -> std::string {
        if (!http.is_running()) {
            return "HTTP: stopped";
        }
        return "HTTP: running at " + http.url();
    };

    ghidrasql::CommandCallbacks callbacks;
    callbacks.get_tables = [&]() {
        auto tables = engine.list_tables();
        std::vector<std::string> lines;
        lines.reserve(tables.size() + 1);
        lines.push_back("Tables/Views:");
        for (const auto& t : tables) {
            lines.push_back("  " + t);
        }
        return join_lines(lines);
    };
    callbacks.get_schema = [&](const std::string& table) { return engine.schema_for(table); };
    callbacks.get_info = [&]() { return engine.info(); };
    callbacks.save_database = [&]() {
        bool ok = source->save_database();
        return ok ? std::string("save_database: ok") : std::string("save_database: not supported/failed");
    };
    callbacks.discard_changes = [&]() {
        bool ok = source->discard_changes();
        return ok ? std::string("discard_changes: ok") : std::string("discard_changes: not supported/failed");
    };
    callbacks.refresh_database = [&]() {
        bool ok = engine.refresh();
        return ok ? std::string("refresh_database: ok") : std::string("refresh_database: not supported/failed");
    };
    callbacks.http_start = http_start;
    callbacks.http_stop = http_stop;
    callbacks.http_status = http_status;

    if (is_tty) {
        std::cout
            << "ghidrasql interactive mode\n"
            << "type .help for commands, .quit to exit\n";
    }

    std::string line;
    std::string statement;
    while (!g_stop.load()) {
        if (is_tty) {
            std::cout << (statement.empty() ? "ghidrasql> " : "      ...> ");
            std::cout.flush();
        }
        if (!std::getline(std::cin, line)) {
            break;
        }

        if (statement.empty()) {
            std::string cmd_out;
            auto cmd = ghidrasql::handle_command(line, callbacks, cmd_out);
            if (cmd == ghidrasql::CommandResult::Quit) {
                break;
            }
            if (cmd == ghidrasql::CommandResult::Handled) {
                if (!cmd_out.empty()) {
                    std::cout << cmd_out << "\n";
                }
                continue;
            }
        }

        statement += line;
        statement += "\n";
        std::vector<std::string> statements;
        std::string parse_error;
        if (xsql::collect_statements(statement, statements, parse_error)
            && !statements.empty()) {
            std::vector<ghidrasql::QueryResult> results;
            std::string error;
            if (engine.execute_script(statement, results, error)) {
                for (const auto& result : results) {
                    print_result(result, format);
                }
            } else {
                for (const auto& result : results) {
                    print_result(result, format);
                }
                if (!error.empty()) {
                    std::cerr << "error: " << error << "\n";
                }
            }
            statement.clear();
        }
    }

    http.stop();
    return 0;
}

#ifdef GHIDRASQL_HAS_LIBGHIDRA
libghidra::client::HeadlessOptions make_headless_opts(const Args& args) {
    libghidra::client::HeadlessOptions opts;
    opts.ghidra_dir = args.ghidra;
    if (!args.binary_paths.empty()) {
        opts.binary = args.binary_paths.front();
        opts.binaries.assign(args.binary_paths.begin() + 1, args.binary_paths.end());
    }
    if (!args.programs.empty()) {
        opts.program = normalize_project_program_arg(args.programs.front());
        for (auto it = args.programs.begin() + 1; it != args.programs.end(); ++it) {
            opts.programs.push_back(normalize_project_program_arg(*it));
        }
    }
    opts.initial_program = normalize_project_program_arg(args.initial_program);
    opts.port = args.rpc_port;
    opts.bind = "127.0.0.1";
    opts.project_dir = args.project;
    opts.project_name = args.project_name;
    opts.analyze = args.analyze;
    opts.overwrite = true;
    opts.shutdown = args.shutdown;
    opts.auth_token = args.auth_token;
    opts.max_runtime_seconds = args.max_runtime;
    opts.extra_headless_args = args.extra_headless_args;
    opts.on_output = [](const std::string& line) {
        std::cout << line << "\n";
    };
    return opts;
}

int run_headless_live_query_local(const Args& args) {
    namespace fs = std::filesystem;

    std::error_code mkdir_ec;
    fs::create_directories(fs::path(args.project), mkdir_ec);
    if (mkdir_ec) {
        std::cerr << "failed to create --project " << args.project
                  << ": " << mkdir_ec.message() << "\n";
        return 1;
    }

    maybe_delete_project(args);

    auto opts = make_headless_opts(args);
    std::cout
        << "Launching Ghidra headless API host\n"
        << "  ghidra:   " << opts.ghidra_dir << "\n"
        << "  bind:     " << opts.bind << "\n"
        << "  port:     " << opts.port << "\n"
        << "  readonly: " << (args.readonly ? "yes" : "no") << "\n"
        << "  shutdown: " << args.shutdown << "\n"
        << std::flush;

    std::optional<libghidra::client::HeadlessClient> headless;
    try {
        headless.emplace(libghidra::client::LaunchHeadless(std::move(opts)));
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    ghidrasql::LibGhidraSourceOptions source_opts;
    source_opts.base_url = headless->base_url();
    source_opts.auth_token = args.auth_token;
    source_opts.auto_open_program = false;
    source_opts.read_only = args.readonly;
    source_opts.auto_save_interval = args.auto_save_interval;
    source_opts.read_timeout_ms = args.rpc_timeout_ms;

    auto source = ghidrasql::create_libghidra_live_source(source_opts);
    if (!source) {
        std::cerr
            << "libghidra source unavailable in this build "
            << "(rebuild with GHIDRASQL_WITH_LIBGHIDRA and libghidra)\n";
        return 1;
    }

    int exit_code = 0;
    ghidrasql::QueryEngine engine(source);
    if (args.list_project_programs) {
        exit_code = print_project_programs(engine, args.format);
    } else if (!args.query.empty()) {
        auto result = engine.query(args.query);
        print_result(result, args.format);
        if (!result.success) {
            exit_code = 1;
        }
    } else if (!args.sql_file.empty()) {
        exit_code = run_script(engine, args.sql_file, args.format);
    } else {
        ghidrasql::HttpServer http;
        ghidrasql::HttpServer::Options http_options;
        http_options.port = 0;
        http_options.bind_address = args.bind;
        http_options.auth_token = args.auth_token;
        exit_code = run_repl(engine, source, http, http_options, args.format);
    }

    if (args.keep_host) {
        std::cout << "Host kept running at " << headless->base_url() << "\n";
        headless->detach();
    } else {
        const bool save = (args.shutdown != "discard" && args.shutdown != "none");
        int rc = headless->close(save);
        if (rc != 0) {
            std::cerr << "analyzeHeadless exited with code " << rc << "\n";
            if (exit_code == 0) exit_code = 1;
        }
    }

    return exit_code;
}

int run_headless_live_server(const Args& args) {
    namespace fs = std::filesystem;

    // Ensure the RPC port doesn't collide with ghidrasql's HTTP port
    if (args.bind == "127.0.0.1" && args.port == args.rpc_port) {
        std::cerr
            << "port collision: headless API endpoint (127.0.0.1:" << args.rpc_port
            << ") matches ghidrasql server endpoint (" << args.bind << ":" << args.port << ")\n"
            << "use --port or --rpc-port to set different ports\n";
        return 1;
    }

    std::error_code mkdir_ec;
    fs::create_directories(fs::path(args.project), mkdir_ec);
    if (mkdir_ec) {
        std::cerr << "failed to create --project " << args.project
                  << ": " << mkdir_ec.message() << "\n";
        return 1;
    }

    maybe_delete_project(args);

    auto opts = make_headless_opts(args);
    std::cout
        << "Launching Ghidra headless API host + ghidrasql HTTP server\n"
        << "  ghidra:        " << opts.ghidra_dir << "\n"
        << "  headless API:  http://" << opts.bind << ":" << opts.port << "\n"
        << "  ghidrasql API: http://" << args.bind << ":" << args.port << "\n"
        << "  readonly:      " << (args.readonly ? "yes" : "no") << "\n"
        << "  shutdown:      " << args.shutdown << "\n"
        << std::flush;

    std::optional<libghidra::client::HeadlessClient> headless;
    try {
        headless.emplace(libghidra::client::LaunchHeadless(std::move(opts)));
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }

    ghidrasql::LibGhidraSourceOptions source_opts;
    source_opts.base_url = headless->base_url();
    source_opts.auth_token = args.auth_token;
    source_opts.auto_open_program = false;
    source_opts.read_only = args.readonly;
    source_opts.auto_save_interval = args.auto_save_interval;
    source_opts.read_timeout_ms = args.rpc_timeout_ms;

    auto source = ghidrasql::create_libghidra_live_source(source_opts);
    if (!source) {
        std::cerr
            << "libghidra source unavailable in this build "
            << "(rebuild with GHIDRASQL_WITH_LIBGHIDRA and libghidra)\n";
        return 1;
    }

    ghidrasql::QueryEngine engine(source);
    ghidrasql::HttpServer http;

    ghidrasql::HttpServer::Options http_options;
    http_options.port = args.port;
    http_options.bind_address = args.bind;
    http_options.auth_token = args.auth_token;

    const int started_port = http.start(
        [&](const std::string& sql, xsql::ScriptStatementResult& out) {
            const ghidrasql::QueryResult r = engine.query(sql);
            out.columns = r.columns;
            out.rows.reserve(r.rows.size());
            for (const auto& row : r.rows) out.rows.push_back(row.values);
            out.success = r.success;
            out.error = r.error;
            out.elapsed_ms = r.elapsed_ms;
        },
        [&]() { return engine.info(); },
        http_options,
        [&]() { return engine.refresh(); });
    if (started_port <= 0) {
        std::cerr << "failed to start ghidrasql HTTP server\n";
        const bool save = (args.shutdown != "discard" && args.shutdown != "none");
        headless->close(save);
        return 1;
    }

    std::cout << "HTTP started at " << http.url() << "\n";

    int exit_code = 0;
    while (!g_stop.load() && http.is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Surface shutdown progress to /shutdown/status pollers so operators
    // can distinguish "HTTP stopped" from "Java exiting" from "complete".
    // /shutdown/status remains observable while the listener tears down
    // because the status endpoint is served by the same listener — once
    // the listener is fully stopped, status polls fail by design (the
    // operator should know shutdown is past observability via that route
    // and either fall back to OS-level checks or wait for the wrapper to exit).
    http.set_shutdown_phase(ghidrasql::HttpServer::ShutdownPhase::kHttpStopping);
    if (g_stop.load() && http.is_running()) {
        http.stop();
    }
    http.set_shutdown_phase(ghidrasql::HttpServer::ShutdownPhase::kJavaExiting);

    const bool save = (args.shutdown != "discard" && args.shutdown != "none");
    int rc = headless->close(save);
    http.set_shutdown_phase(rc == -2
        ? ghidrasql::HttpServer::ShutdownPhase::kForceKilled
        : ghidrasql::HttpServer::ShutdownPhase::kComplete);
    if (rc != 0) {
        std::cerr << "analyzeHeadless exited with code " << rc << "\n";
        if (exit_code == 0) exit_code = 1;
    }

    return exit_code;
}
#endif

}  // namespace

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) {
        print_help();
        return 1;
    }

    if (args.help) {
        print_help();
        return 0;
    }

    if (args.version) {
        std::cout << "ghidrasql version " GHIDRASQL_VERSION "\n";
        return 0;
    }

    std::signal(SIGINT, signal_handler);

    // Fall back to GHIDRA_INSTALL_DIR only when no explicit connect mode was
    // requested.  --url must remain pure connect mode even if the environment
    // has a default Ghidra install path.
    if (args.ghidra.empty() && args.url.empty()) {
        const char* env = std::getenv("GHIDRA_INSTALL_DIR");
        if (env && *env) {
            args.ghidra = env;
        }
    }

    // Mode auto-detection
    const bool has_ghidra = !args.ghidra.empty();
    const bool has_url = !args.url.empty();

    if (has_ghidra && has_url) {
        std::cerr << "error: --ghidra and --url are mutually exclusive\n"
                  << "  use --ghidra <path> for headless mode, or\n"
                  << "  use --url <url> to connect to a running LibGhidraHost\n";
        return 1;
    }

    if (!has_ghidra && !has_url) {
        std::cerr
            << "error: no connection mode specified\n"
            << "  use --ghidra <path> for headless mode (launch Ghidra, run queries, shut down), or\n"
            << "  use --url <url> to connect to a running LibGhidraHost\n";
        return 1;
    }

    if (args.list_project_programs &&
        (args.serve || !args.query.empty() || !args.sql_file.empty() || args.interactive)) {
        std::cerr << "--list-project-programs cannot be combined with --http, -q, -f, or -i\n";
        return 1;
    }

    // Headless mode (--ghidra)
    if (has_ghidra) {
        if (!validate_headless_args(args)) {
            return 1;
        }
        if (args.serve && (!args.query.empty() || !args.sql_file.empty() || args.interactive)) {
            std::cerr << "headless --http cannot be combined with -q/-f/-i\n";
            return 1;
        }
        if (args.serve) {
#ifdef GHIDRASQL_HAS_LIBGHIDRA
            return run_headless_live_server(args);
#else
            std::cerr
                << "headless serve mode requires libghidra source support "
                << "(rebuild with GHIDRASQL_WITH_LIBGHIDRA=ON)\n";
            return 1;
#endif
        }
#ifdef GHIDRASQL_HAS_LIBGHIDRA
        return run_headless_live_query_local(args);
#else
        std::cerr
            << "headless mode requires libghidra source support "
            << "(rebuild with GHIDRASQL_WITH_LIBGHIDRA=ON)\n";
        return 1;
#endif
    }

    // Connect mode (--url)
    std::shared_ptr<ghidrasql::Source> source;
    ghidrasql::LibGhidraSourceOptions opts;
    opts.base_url = args.url;
    opts.auth_token = args.auth_token;

    const std::string selected_program = selected_program_arg(args);

    // Auto-open when --project + --program/--initial-program are both set.
    const bool has_open_params = !args.project.empty() && !selected_program.empty();
    opts.auto_open_program = has_open_params;
    opts.project_path = args.project;
    opts.project_name = args.project_name;
    opts.program_path = selected_program;
    opts.analyze = args.analyze && args.analyze_explicit;
    opts.read_only = args.readonly;
    opts.auto_save_interval = args.auto_save_interval;
    opts.read_timeout_ms = args.rpc_timeout_ms;
    source = ghidrasql::create_libghidra_live_source(opts);
    if (!source) {
        std::cerr
            << "libghidra source unavailable in this build "
            << "(rebuild with GHIDRASQL_WITH_LIBGHIDRA and libghidra)\n";
        return 1;
    }
    std::cout << "Using libghidra source at " << args.url << "\n";

    ghidrasql::QueryEngine engine(source);
    ghidrasql::HttpServer http;

    ghidrasql::HttpServer::Options http_options;
    http_options.port = args.port;
    http_options.bind_address = args.bind;
    http_options.auth_token = args.auth_token;

    if (args.serve) {
        int started_port = http.start(
            [&](const std::string& sql, xsql::ScriptStatementResult& out) {
                const ghidrasql::QueryResult r = engine.query(sql);
                out.columns = r.columns;
                out.rows.reserve(r.rows.size());
                for (const auto& row : r.rows) out.rows.push_back(row.values);
                out.success = r.success;
                out.error = r.error;
                out.elapsed_ms = r.elapsed_ms;
            },
            [&]() { return engine.info(); },
            http_options,
            [&]() { return engine.refresh(); });
        if (started_port <= 0) {
            std::cerr << "failed to start HTTP server\n";
            return 1;
        }
        std::cout << "HTTP started at " << http.url() << "\n";
    }

    if (args.list_project_programs) {
        return print_project_programs(engine, args.format);
    }

    if (!args.query.empty()) {
        auto result = engine.query(args.query);
        print_result(result, args.format);
        return result.success ? 0 : 1;
    }

    if (!args.sql_file.empty()) {
        return run_script(engine, args.sql_file, args.format);
    }

    const bool repl = args.interactive || (!args.serve && args.query.empty() && args.sql_file.empty());
    if (!repl) {
        while (!g_stop.load()) {
            if (!http.is_running()) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        http.stop();
        return 0;
    }

    return run_repl(engine, source, http, http_options, args.format);
}
