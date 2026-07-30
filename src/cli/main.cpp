// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#include <ghidrasql/ghidrasql.hpp>
#include <ghidrasql/source.hpp>

#include "request_params.hpp"

#ifdef GHIDRASQL_HAS_MCP
#include "../common/mcp_server.hpp"
#endif

#include <xsql/script.hpp>
#include <xsql/query_script.hpp>
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
#include <cctype>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
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

    // MCP server (optional, gated by GHIDRASQL_HAS_MCP at build time)
    bool mcp = false;
    int mcp_port = 0;  // 0 = OS-assigned ephemeral port

    // Connection (pick one)
    std::string url;       // --url <url>   → connect mode
    std::string ghidra;    // --ghidra <path> → headless mode

    // Program/project (shared)
    std::string binary_path;
    std::vector<std::string> binary_paths;
    std::string program;
    std::vector<std::string> programs;
    bool list_project_programs = false;
    std::string project;
    std::string project_name;
    bool analyze = true;        // default: analyze in headless
    bool analyze_explicit = false;
    bool load_libraries = false; // default: imports skip external system libraries
    bool readonly = false;
    bool fresh = false;

    // Lifecycle (headless)
    std::string shutdown;       // save|discard|none
    bool shutdown_explicit = false;
    bool keep_host = false;
    int max_runtime = 600;
    bool max_runtime_explicit = false;

    // Default is the ephemeral sentinel (0): when the CLI SPAWNS a headless
    // host and the user did not pass --rpc-port, the host binds an OS-assigned
    // port (no fixed-18080 collisions across concurrent instances). 18080 is
    // only used when the user explicitly pins it (rpc_port_explicit), or as the
    // conventional port a manually-started standalone host uses for --url
    // clients. See make_headless_project_opts.
    int rpc_port = 18080;
    bool rpc_port_explicit = false;
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
    {"--initial-program",       "use --program <name> to select the active project program"},
};

static constexpr const char* GHIDRASQL_COPYRIGHT = "Copyright (c) 2024-2026 Elias Bachaalany";

void print_help() {
    std::cout
        << "ghidrasql v" GHIDRASQL_VERSION " - SQL interface for Ghidra analysis data\n"
        << GHIDRASQL_COPYRIGHT << "\n\n"
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
        << "  --mcp [port]               Start MCP (Model Context Protocol) SSE server\n"
        << "                             (built only when -DGHIDRASQL_WITH_MCP=ON; port 0 = random 1024-65535)\n"
        << "  --list-project-programs    List programs in the current/opened project and exit\n"
        << "  --format <fmt>             Output format: table (default) or json\n\n"
        << "Program/project:\n"
        << "  --binary <path>            Raw binary (.exe/.dll/firmware/etc.) to import.\n"
        << "                             Triggers fresh Ghidra headless analysis; the\n"
        << "                             resulting program lands in the working project.\n"
        << "                             Imports skip loading external system libraries by\n"
        << "                             default (fast); pass --load-libraries to include them.\n"
        << "                             Headless mode only; repeatable for multi-binary projects.\n"
        << "  --program <name>           Existing program inside the project (repeatable).\n"
        << "                             Use this to reopen an already-imported program; use\n"
        << "                             --binary to import a fresh one.\n"
        << "  --project <dir>            Project directory\n"
        << "  --project-name <name>      Project name\n"
        << "  --analyze                  Run analysis (default in headless)\n"
        << "  --no-analyze               Skip analysis\n"
        << "  --load-libraries           Load/link external system libraries during --binary\n"
        << "                             import (ordinal->name resolution). Off by default;\n"
        << "                             slower, and pulls kernel32/CRT into the project.\n"
        << "  --readonly                 Read-only session\n\n"
        << "Server/network:\n"
        << "  --port <n>                 HTTP port (default: 8081)\n"
        << "  --bind <addr>              Bind address (default: 127.0.0.1)\n"
        << "  --auth <token>             Bearer auth token\n\n"
        << "Lifecycle (headless):\n"
        << "  --shutdown <mode>          save|discard|none (default: save; discard when --readonly)\n"
        << "  --keep-host                Don't auto-shutdown after query\n"
        << "  --max-runtime <sec>        Host lifetime bound (0=disable; default: 0 for\n"
        << "                             --http serve mode, 600 for one-shot/-q/-f/-i)\n"
        << "  --rpc-port <n>             LibGhidraHost RPC port (headless only). Default is an\n"
        << "                             auto-assigned (ephemeral) port, so several ghidrasql\n"
        << "                             instances never collide on the internal RPC port. Pass\n"
        << "                             a value to pin it (18080 is the conventional port a\n"
        << "                             standalone host uses for --url clients).\n"
        << "  --rpc-timeout-ms <n>       Per-RPC read timeout (0=libghidra default 120000)\n"
        << "  --fresh                    Delete existing project first\n"
        << "  --auto-save <n>            Save every N mutations (0=disabled, default)\n\n"
        << "Meta:\n"
        << "  -h, --help                 Show this help\n"
        << "  --version                  Show version\n";
}

// Parse a TCP port from a full numeric string. Rejects trailing garbage
// (e.g. "18080xyz") and out-of-range values, unlike a bare std::stoi which
// silently truncates at the first non-digit. Returns false on any rejection.
// allow_zero permits the sentinel 0 (used by --mcp, where 0 = pick a random
// port in 1024-65535); without it the valid range is 1-65535.
bool parse_port_string(const std::string& s, int& out, bool allow_zero = false) {
    if (s.empty()) {
        return false;
    }
    for (char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    errno = 0;
    char* end = nullptr;
    const long v = std::strtol(s.c_str(), &end, 10);
    const long min_v = allow_zero ? 0 : 1;
    if (end == s.c_str() || *end != '\0' || errno == ERANGE || v < min_v || v > 65535) {
        return false;
    }
    out = static_cast<int>(v);
    return true;
}

// Parse a non-negative integer from a full numeric string (0 .. INT_MAX).
// Same full-string strictness as parse_port_string (rejects trailing garbage,
// signs, and overflow) but without a port range -- for CLI options like
// --rpc-timeout-ms / --max-runtime / --auto-save where any non-negative value
// is valid.
bool parse_nonnegative_int_string(const std::string& s, int& out) {
    if (s.empty()) {
        return false;
    }
    for (char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
    }
    errno = 0;
    char* end = nullptr;
    const long v = std::strtol(s.c_str(), &end, 10);
    if (end == s.c_str() || *end != '\0' || errno == ERANGE || v < 0 || v > INT_MAX) {
        return false;
    }
    out = static_cast<int>(v);
    return true;
}

// Validate that the ports the requested servers will bind do not collide.
// All servers share args.bind, so two servers on the same explicit port always
// collide regardless of the bind address. rpc_active means the headless RPC
// API endpoint is in play (headless mode only). A port of 0 means "pick a
// random/ephemeral port" and is never treated as a collision.
//
// The EFFECTIVE spawned-host RPC port is ephemeral (0) unless the user pinned
// --rpc-port (rpc_port_explicit) — mirror make_headless_project_opts here so an
// unpinned --rpc-port cannot be reported as colliding with --port/--mcp: an
// OS-assigned port can never collide with a fixed one.
bool validate_server_ports(const Args& args, bool rpc_active) {
    auto same = [](int a, int b) { return a > 0 && b > 0 && a == b; };
    const int effective_rpc_port = args.rpc_port_explicit ? args.rpc_port : 0;
    if (args.serve && rpc_active && same(args.port, effective_rpc_port)) {
        std::cerr << "port collision: HTTP server (" << args.port
                  << ") matches headless RPC endpoint (" << effective_rpc_port << ")\n"
                  << "use --port or --rpc-port to set different ports\n";
        return false;
    }
    if (args.mcp && args.serve && same(args.port, args.mcp_port)) {
        std::cerr << "port collision: HTTP server (" << args.port
                  << ") matches MCP server (" << args.mcp_port << ")\n"
                  << "use --port or --mcp to set different ports\n";
        return false;
    }
    if (args.mcp && rpc_active && same(effective_rpc_port, args.mcp_port)) {
        std::cerr << "port collision: headless RPC endpoint (" << effective_rpc_port
                  << ") matches MCP server (" << args.mcp_port << ")\n"
                  << "use --rpc-port or --mcp to set different ports\n";
        return false;
    }
    return true;
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
        } else if (arg == "--mcp") {
            args.mcp = true;
            // Optional port: --mcp [N]. Only consume the next token when it
            // looks like a port (leading digit); validate it fully so trailing
            // garbage or out-of-range fails loudly instead of silently
            // truncating (e.g. "--mcp 18080xyz" -> 18080).
            if (i + 1 < argc && std::isdigit(static_cast<unsigned char>(argv[i + 1][0]))) {
                int p = 0;
                // --mcp accepts 0 as the documented "random 1024-65535" sentinel
                // (mcp_server picks the port when mcp_port == 0).
                if (!parse_port_string(argv[i + 1], p, /*allow_zero=*/true)) {
                    std::cerr << "invalid value for --mcp: " << argv[i + 1]
                              << " (expected port 0-65535; 0 = random 1024-65535)\n";
                    return false;
                }
                args.mcp_port = p;
                ++i;
            }
        } else if (arg == "--list-project-programs") {
            args.list_project_programs = true;
        } else if (arg == "--port") {
            if (++i >= argc) {
                std::cerr << "missing value for --port\n";
                return false;
            }
            // Full-string strict parse (rejects "8081junk" and out-of-range).
            if (!parse_port_string(argv[i], args.port)) {
                std::cerr << "invalid --port value: " << argv[i] << "\n";
                return false;
            }
        } else if (arg == "--rpc-port") {
            if (++i >= argc) {
                std::cerr << "missing value for --rpc-port\n";
                return false;
            }
            if (!parse_port_string(argv[i], args.rpc_port)) {
                std::cerr << "invalid --rpc-port value: " << argv[i] << "\n";
                return false;
            }
            args.rpc_port_explicit = true;
        } else if (arg == "--rpc-timeout-ms") {
            if (++i >= argc) {
                std::cerr << "missing value for --rpc-timeout-ms\n";
                return false;
            }
            if (!parse_nonnegative_int_string(argv[i], args.rpc_timeout_ms)) {
                std::cerr << "invalid --rpc-timeout-ms value: " << argv[i]
                          << " (expected >= 0)\n";
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
        } else if (arg == "--load-libraries") {
            args.load_libraries = true;
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
            if (!parse_nonnegative_int_string(argv[i], args.max_runtime)) {
                std::cerr << "invalid --max-runtime value: " << argv[i]
                          << " (expected >= 0)\n";
                return false;
            }
            args.max_runtime_explicit = true;
        } else if (arg == "--auto-save") {
            if (++i >= argc) {
                std::cerr << "missing value for --auto-save\n";
                return false;
            }
            if (!parse_nonnegative_int_string(argv[i], args.auto_save_interval)) {
                std::cerr << "invalid --auto-save value: " << argv[i]
                          << " (expected >= 0)\n";
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
    if (args.readonly && !args.binary_paths.empty()) {
        std::cerr << "--readonly cannot be combined with --binary imports\n";
        ok = false;
    }
    // --port / --rpc-port / --max-runtime ranges are enforced at parse time
    // (parse_port_string / parse_nonnegative_int_string), so no post-parse range
    // re-check is needed here.
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

    // The QueryEngine is not concurrency-safe: the `.http` server runs on httplib
    // worker threads while the REPL evaluates queries on this thread. Serialize
    // all engine access (HTTP callbacks + interactive execution) under one mutex.
    std::mutex session_mu;

    auto http_start = [&]() -> std::string {
        if (http.is_running()) {
            return "HTTP already running at " + http.url();
        }
        int port = http.start(
            [&](const std::string& sql, const xsql::ScriptOptions& opts) {
                std::lock_guard<std::mutex> lock(session_mu);
                return engine.run_script(sql, opts);
            },
            [&]() {
                std::lock_guard<std::mutex> lock(session_mu);
                return engine.info();
            },
            http_options,
            [&]() {
                std::lock_guard<std::mutex> lock(session_mu);
                return engine.refresh();
            });
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

    // Every REPL command that touches the engine or the shared source must take
    // session_mu: an active `.http` server runs the engine on worker threads, so
    // an overlapping `.tables`/`.schema`/`.info`/`.refresh`/`.save`/`.discard`
    // would otherwise race it.
    ghidrasql::CommandCallbacks callbacks;
    callbacks.get_tables = [&]() {
        std::lock_guard<std::mutex> lock(session_mu);
        auto tables = engine.list_tables();
        std::vector<std::string> lines;
        lines.reserve(tables.size() + 1);
        lines.push_back("Tables/Views:");
        for (const auto& t : tables) {
            lines.push_back("  " + t);
        }
        return join_lines(lines);
    };
    callbacks.get_schema = [&](const std::string& table) {
        std::lock_guard<std::mutex> lock(session_mu);
        return engine.schema_for(table);
    };
    callbacks.get_info = [&]() {
        std::lock_guard<std::mutex> lock(session_mu);
        return engine.info();
    };
    callbacks.save_database = [&]() {
        std::lock_guard<std::mutex> lock(session_mu);
        bool ok = source->save_database();
        return ok ? std::string("save_database: ok") : std::string("save_database: not supported/failed");
    };
    callbacks.discard_changes = [&]() {
        std::lock_guard<std::mutex> lock(session_mu);
        bool ok = source->discard_changes();
        return ok ? std::string("discard_changes: ok") : std::string("discard_changes: not supported/failed");
    };
    callbacks.refresh_database = [&]() {
        std::lock_guard<std::mutex> lock(session_mu);
        bool ok = engine.refresh();
        return ok ? std::string("refresh_database: ok") : std::string("refresh_database: not supported/failed");
    };
    callbacks.http_start = http_start;
    callbacks.http_stop = http_stop;
    callbacks.http_status = http_status;

    if (is_tty) {
        std::cout
            << "ghidrasql interactive mode\n"
            << GHIDRASQL_COPYRIGHT << "\n"
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
            bool ok;
            {
                // Hold the lock only for engine execution, not the printing.
                std::lock_guard<std::mutex> lock(session_mu);
                ok = engine.execute_script(statement, results, error);
            }
            if (ok) {
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
// Human-readable label for a requested RPC port before the host is up: an
// ephemeral request (0) has no assigned port yet, so show "auto (ephemeral)"
// rather than a misleading literal 0. The resolved port is printed from
// base_url() once the host reports its READY banner.
std::string headless_port_label(int port) {
    return port == 0 ? "auto (ephemeral)" : std::to_string(port);
}

libghidra::client::HeadlessProjectOptions make_headless_project_opts(const Args& args) {
    libghidra::client::HeadlessProjectOptions opts;
    opts.ghidra_dir = args.ghidra;
    // Ephemeral RPC port by default for CLI-SPAWNED hosts: the RPC port is
    // purely internal plumbing between this CLI and the JVM it spawns (end
    // users talk to the SQL HTTP port, or connect to a standalone host via
    // --url), so a fixed 18080 only invites collisions across concurrent
    // instances. Pass 0 (OS-assigned) unless the user pinned --rpc-port. The
    // real bound port is reported back in the READY banner and reflected in
    // HeadlessClient::base_url().
    opts.port = args.rpc_port_explicit ? args.rpc_port : 0;
    opts.bind = "127.0.0.1";
    opts.project_dir = args.project;
    opts.project_name = args.project_name;
    opts.shutdown = args.shutdown;
    opts.auth_token = args.auth_token;
    opts.max_runtime_seconds = args.max_runtime;
    opts.extra_headless_args = args.extra_headless_args;
    if (args.rpc_timeout_ms > 0) {
        opts.read_timeout = std::chrono::milliseconds(args.rpc_timeout_ms);
    }
    opts.on_output = [](const std::string& line) {
        std::cout << line << "\n";
    };
    return opts;
}

struct HeadlessProjectSession {
    std::string active_program_path;
    std::vector<std::string> imported_program_paths;
};

std::string json_error(std::string message) {
    return xsql::json{{"success", false}, {"error", std::move(message)}}.dump();
}

using ghidrasql::cli::string_from_json_or_raw;

bool bool_from_json(
    const std::string& body,
    const std::string& key,
    bool fallback)
{
    try {
        auto j = xsql::json::parse(body);
        if (j.is_object() && j.contains(key) && j[key].is_boolean()) {
            return j[key].get<bool>();
        }
    } catch (...) {
    }
    return fallback;
}

libghidra::client::ShutdownPolicy shutdown_policy_from_string(const std::string& raw) {
    const std::string value = to_lower(raw);
    if (value == "discard") {
        return libghidra::client::ShutdownPolicy::kDiscard;
    }
    if (value == "none") {
        return libghidra::client::ShutdownPolicy::kNone;
    }
    return libghidra::client::ShutdownPolicy::kSave;
}

bool import_programs_and_open_active(
    libghidra::client::HeadlessClient& headless,
    const Args& args,
    HeadlessProjectSession& session)
{
    session = {};
    for (const auto& binary_path : args.binary_paths) {
        libghidra::client::ImportProgramRequest req;
        req.source_path = binary_path;
        req.overwrite = true;
        req.analyze = args.analyze;
        // Off by default (LibGhidraHost skips external libraries); --load-libraries
        // re-enables the loader's ordinal lookup / library load+link. The arg set
        // is shared with the HTTP /project/import handler via import_loader_args.
        req.loader_args =
            ghidrasql::cli::import_loader_args<libghidra::client::LoaderArg>(
                args.load_libraries);
        auto imported = headless->ImportProgram(req);
        if (!imported.ok()) {
            std::cerr << "ImportProgram failed for " << binary_path
                      << ": " << imported.status.message << "\n";
            return false;
        }
        for (const auto& path : imported.value->program_paths) {
            session.imported_program_paths.push_back(path);
        }
        if (session.active_program_path.empty()) {
            session.active_program_path = imported.value->primary_program_path;
        }
    }

    const std::string selected_program = selected_program_arg(args);
    if (!selected_program.empty()) {
        session.active_program_path = selected_program;
    }

    if (session.active_program_path.empty()) {
        return true;
    }

    libghidra::client::OpenProgramRequest open_req;
    open_req.project_path = args.project;
    open_req.project_name = args.project_name;
    open_req.program_path = session.active_program_path;
    // Honor the headless --analyze default (true) when opening an existing
    // program too; without this an existing --program reopen always behaved as
    // analyze=false, ignoring the documented default and forcing users to do
    // nothing for fast reopens (only --no-analyze should skip analysis).
    open_req.analyze = args.analyze;
    open_req.read_only = args.readonly;
    auto opened = headless->OpenProgram(open_req);
    if (!opened.ok()) {
        std::cerr << "OpenProgram failed for " << session.active_program_path
                  << ": " << opened.status.message << "\n";
        return false;
    }
    return true;
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

    auto opts = make_headless_project_opts(args);
    const std::string headless_bind = opts.bind;
    std::cout
        << "Launching Ghidra headless API host\n"
        << "  ghidra:   " << opts.ghidra_dir << "\n"
        << "  bind:     " << opts.bind << "\n"
        << "  port:     " << headless_port_label(opts.port) << "\n"
        << "  readonly: " << (args.readonly ? "yes" : "no") << "\n"
        << "  shutdown: " << args.shutdown << "\n"
        << std::flush;

    std::optional<libghidra::client::HeadlessClient> headless;
    try {
        headless.emplace(libghidra::client::LaunchHeadlessProject(std::move(opts)));
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
    // Echo the RESOLVED port once the host is up (base_url reflects the actual
    // bound port, which for an ephemeral request was assigned by the OS).
    std::cout << "  headless API: " << headless->base_url() << "\n" << std::flush;

    HeadlessProjectSession session;
    if (!import_programs_and_open_active(*headless, args, session)) {
        const bool save = (args.shutdown != "discard" && args.shutdown != "none");
        headless->close(save);
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

    // Ensure the headless RPC port doesn't collide with the HTTP or MCP server
    // ports. This must run whether or not --http is serving (an --mcp-only
    // headless server can still collide --mcp with the default --rpc-port).
    if (!validate_server_ports(args, /*rpc_active=*/true)) {
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

    auto opts = make_headless_project_opts(args);
    std::cout
        << "Launching Ghidra headless API host + ghidrasql server\n"
        << "  ghidra:        " << opts.ghidra_dir << "\n"
        << "  headless RPC:  http://" << opts.bind << ":"
        << headless_port_label(opts.port) << "\n";
    if (args.serve) {
        std::cout << "  ghidrasql API: http://" << args.bind << ":" << args.port << "\n";
    }
    if (args.mcp) {
        std::cout << "  ghidrasql MCP: enabled\n";
    }
    std::cout
        << "  readonly:      " << (args.readonly ? "yes" : "no") << "\n"
        << "  shutdown:      " << args.shutdown << "\n"
        << std::flush;

    std::optional<libghidra::client::HeadlessClient> headless;
    try {
        headless.emplace(libghidra::client::LaunchHeadlessProject(std::move(opts)));
    } catch (const std::exception& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
    // Report the RESOLVED headless RPC endpoint (base_url reflects the actual
    // bound port, OS-assigned when the request was ephemeral).
    std::cout << "  headless RPC (resolved): " << headless->base_url() << "\n"
              << std::flush;

    HeadlessProjectSession session;
    if (!import_programs_and_open_active(*headless, args, session)) {
        const bool save = (args.shutdown != "discard" && args.shutdown != "none");
        headless->close(save);
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
    // Declared before `http` so it outlives the server whose worker threads use
    // it: HTTP worker lambdas (and the MCP callback) capture &session_mu, and
    // ~HttpServer::stop() joins those workers. Reverse-order destruction would
    // otherwise destroy session_mu first, then join workers that lock it (UAF).
    // Mirrors connect serve mode.
    std::mutex session_mu;
    ghidrasql::HttpServer http;

    ghidrasql::HttpServer::Options http_options;
    http_options.port = args.port;
    http_options.bind_address = args.bind;
    http_options.auth_token = args.auth_token;

    auto list_programs_json = [&]() -> std::string {
        std::lock_guard<std::mutex> lock(session_mu);
        libghidra::client::ListProjectFilesRequest req;
        req.programs_only = true;
        auto listed = (*headless)->ListProjectFiles(req);
        if (!listed.ok()) {
            return json_error("ListProjectFiles failed: " + listed.status.message);
        }
        xsql::json programs = xsql::json::array();
        for (const auto& file : listed.value->files) {
            programs.push_back({
                {"path", file.path},
                {"name", file.name},
                {"folder_path", file.folder_path},
                {"content_type", file.content_type},
                {"domain_object_class", file.domain_object_class},
                {"is_program", file.is_program},
            });
        }
        return xsql::json{{"success", true}, {"programs", std::move(programs)}}.dump();
    };

    auto active_program_json = [&]() -> std::string {
        std::lock_guard<std::mutex> lock(session_mu);
        auto rev = (*headless)->GetRevision();
        if (!rev.ok()) {
            return json_error("GetRevision failed: " + rev.status.message);
        }
        const bool active = rev.value->program_id != 0;
        return xsql::json{
            {"success", true},
            {"active", active},
            {"program_path", active ? rev.value->program_path : session.active_program_path},
            {"program_id", rev.value->program_id},
            {"modification_number", rev.value->modification_number},
            {"file_id", rev.value->file_id},
            {"file_version", rev.value->file_version},
            {"file_last_modified_time", rev.value->file_last_modified_time},
        }.dump();
    };

    auto import_program_json = [&](const std::string& body) -> std::string {
        std::lock_guard<std::mutex> lock(session_mu);
        if (args.readonly) {
            return json_error("cannot import programs in readonly mode");
        }
        const std::string source_path = string_from_json_or_raw(body, "source_path", "path");
        if (source_path.empty()) {
            return json_error("source_path is required");
        }
        libghidra::client::ImportProgramRequest req;
        req.source_path = source_path;
        req.overwrite = bool_from_json(body, "overwrite", true);
        req.analyze = bool_from_json(body, "analyze", args.analyze);
        // External system libraries are skipped by default; a "load_libraries":true
        // body field (or the --load-libraries CLI default) re-enables them. The
        // arg set is shared with the headless startup import via import_loader_args.
        req.loader_args =
            ghidrasql::cli::import_loader_args<libghidra::client::LoaderArg>(
                bool_from_json(body, "load_libraries", args.load_libraries));
        try {
            auto j = xsql::json::parse(body);
            if (j.is_object()) {
                if (j.contains("project_folder_path") && j["project_folder_path"].is_string()) {
                    req.project_folder_path = j["project_folder_path"].get<std::string>();
                }
                if (j.contains("program_name") && j["program_name"].is_string()) {
                    req.program_name = j["program_name"].get<std::string>();
                }
            }
        } catch (...) {
        }
        auto imported = (*headless)->ImportProgram(req);
        if (!imported.ok()) {
            return json_error("ImportProgram failed: " + imported.status.message);
        }
        for (const auto& path : imported.value->program_paths) {
            session.imported_program_paths.push_back(path);
        }
        // Track the imported program as active when nothing is open yet, mirroring
        // the headless startup path — keeps session.active_program_path consistent
        // (/project/active still resolves live via GetRevision either way).
        if (session.active_program_path.empty() &&
            !imported.value->primary_program_path.empty()) {
            session.active_program_path = imported.value->primary_program_path;
        }
        engine.refresh();
        return xsql::json{
            {"success", true},
            {"program_paths", imported.value->program_paths},
            {"primary_program_path", imported.value->primary_program_path},
        }.dump();
    };

    auto open_program_json = [&](const std::string& body) -> std::string {
        std::lock_guard<std::mutex> lock(session_mu);
        std::string program_path = string_from_json_or_raw(body, "program_path", "path");
        program_path = normalize_project_program_arg(program_path);
        if (program_path.empty()) {
            return json_error("program_path is required");
        }
        if (!session.active_program_path.empty() && session.active_program_path != program_path) {
            auto closed = (*headless)->CloseProgram(shutdown_policy_from_string(args.shutdown));
            if (!closed.ok()) {
                return json_error("CloseProgram failed: " + closed.status.message);
            }
            session.active_program_path.clear();
        }
        libghidra::client::OpenProgramRequest req;
        req.project_path = args.project;
        req.project_name = args.project_name;
        req.program_path = program_path;
        req.read_only = args.readonly;
        auto opened = (*headless)->OpenProgram(req);
        if (!opened.ok()) {
            return json_error("OpenProgram failed: " + opened.status.message);
        }
        session.active_program_path = program_path;
        engine.refresh();
        return xsql::json{
            {"success", true},
            {"program_path", program_path},
            {"program_name", opened.value->program_name},
            {"language_id", opened.value->language_id},
            {"compiler_spec", opened.value->compiler_spec},
            {"image_base", opened.value->image_base},
        }.dump();
    };

    auto close_program_json = [&](const std::string& body) -> std::string {
        std::lock_guard<std::mutex> lock(session_mu);
        std::string policy = string_from_json_or_raw(body, "shutdown_policy", "policy");
        if (policy.empty()) {
            policy = args.shutdown;
        }
        auto closed = (*headless)->CloseProgram(shutdown_policy_from_string(policy));
        if (!closed.ok()) {
            return json_error("CloseProgram failed: " + closed.status.message);
        }
        session.active_program_path.clear();
        engine.refresh();
        return xsql::json{{"success", true}, {"closed", closed.value->closed}}.dump();
    };

    ghidrasql::HttpServer::ProjectControlFns project_fns;
    project_fns.list_programs = list_programs_json;
    project_fns.active_program = active_program_json;
    project_fns.import_program = import_program_json;
    project_fns.open_program = open_program_json;
    project_fns.close_program = close_program_json;

    if (args.serve) {
        const int started_port = http.start(
            [&](const std::string& sql, const xsql::ScriptOptions& opts) {
                std::lock_guard<std::mutex> lock(session_mu);
                return engine.run_script(sql, opts);
            },
            [&]() {
                std::lock_guard<std::mutex> lock(session_mu);
                return engine.info();
            },
            http_options,
            [&]() {
                std::lock_guard<std::mutex> lock(session_mu);
                return engine.refresh();
            },
            project_fns);
        if (started_port <= 0) {
            std::cerr << "failed to start ghidrasql HTTP server\n";
            const bool save = (args.shutdown != "discard" && args.shutdown != "none");
            headless->close(save);
            return 1;
        }
        std::cout << "HTTP started at " << http.url() << "\n";
    }

#ifdef GHIDRASQL_HAS_MCP
    std::unique_ptr<ghidrasql::GhidrasqlMcpServer> mcp_server;
    if (args.mcp) {
        mcp_server = std::make_unique<ghidrasql::GhidrasqlMcpServer>();
        const int mcp_started = mcp_server->start(args.mcp_port,
            [&engine, &session_mu](const std::string& sql,
                                   bool continue_on_error,
                                   bool include_sql) {
                std::lock_guard<std::mutex> lock(session_mu);
                xsql::ScriptOptions opts;
                opts.continue_on_error = continue_on_error;
                opts.include_sql = include_sql;
                auto script = ghidrasql::run_script(engine, sql, opts);
                return xsql::script_result_to_json(script, opts.include_sql);
            },
            args.bind,
            args.auth_token);
        if (mcp_started <= 0) {
            std::cerr << "failed to start MCP server\n";
            // Quiesce the HTTP listener before the (seconds-long) headless
            // close so no worker thread is serving /query while we tear down.
            if (http.is_running()) http.stop();
            mcp_server->stop();
            const bool save = (args.shutdown != "discard" && args.shutdown != "none");
            headless->close(save);
            return 1;
        }
        std::cout << ghidrasql::format_mcp_info(mcp_started, args.bind);
    }
#else
    if (args.mcp) {
        std::cerr << "MCP not available in this build "
                     "(rebuild with -DGHIDRASQL_WITH_MCP=ON)\n";
        // Stop the HTTP listener before headless close so no worker thread is
        // serving while we tear down (workers capture &session_mu).
        if (http.is_running()) http.stop();
        const bool save = (args.shutdown != "discard" && args.shutdown != "none");
        headless->close(save);
        return 1;
    }
#endif

    int exit_code = 0;
    // Serve until Ctrl-C / shutdown. When HTTP is serving, its listener owning
    // the loop is the stop signal; an MCP-only headless server (no --http) runs
    // until signaled. An explicit --max-runtime caps the WHOLE process, not just
    // the Java host: the host's own max_runtime_ms makes the Java backend
    // self-exit at the cap, but without this the C++ front door keeps listening,
    // leaving a zombie server (port open, backend gone, every query erroring).
    // Serve mode defaults to no cap (set at parse time), so this only fires when
    // the operator explicitly asked for one.
    const bool have_runtime_cap = args.max_runtime_explicit && args.max_runtime > 0;
    const auto serve_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(args.max_runtime);
    while (!g_stop.load() && (!args.serve || http.is_running())) {
        if (have_runtime_cap &&
            std::chrono::steady_clock::now() >= serve_deadline) {
            std::cout << "max-runtime (" << args.max_runtime
                      << "s) reached; shutting down\n"
                      << std::flush;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Surface shutdown progress to /shutdown/status pollers so operators
    // can distinguish "HTTP stopped" from "Java exiting" from "complete".
    // /shutdown/status remains observable while the listener tears down
    // because the status endpoint is served by the same listener — once
    // the listener is fully stopped, status polls fail by design (the
    // operator should know shutdown is past observability via that route
    // and either fall back to OS-level checks or wait for the wrapper to exit).
    // Stop the listener no matter how the loop ended (signal, listener death,
    // or the --max-runtime deadline). Gating this on g_stop left the HTTP
    // front door serving /query against the closing host on a deadline break.
    http.set_shutdown_phase(ghidrasql::HttpServer::ShutdownPhase::kHttpStopping);
    if (http.is_running()) {
        http.stop();
    }
    http.set_shutdown_phase(ghidrasql::HttpServer::ShutdownPhase::kJavaExiting);

#ifdef GHIDRASQL_HAS_MCP
    // Stop MCP before tearing down the Ghidra host: its worker threads run
    // queries against the RPC host, so they must be quiesced before
    // headless->close() or an in-flight MCP request would hit a closed host.
    if (mcp_server) {
        mcp_server->stop();
    }
#endif

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
        std::cout << "ghidrasql version " GHIDRASQL_VERSION "\n" << GHIDRASQL_COPYRIGHT << "\n";
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
        (args.serve || args.mcp || !args.query.empty() || !args.sql_file.empty() || args.interactive)) {
        std::cerr << "--list-project-programs cannot be combined with --http, --mcp, -q, -f, or -i\n";
        return 1;
    }

    // Headless mode (--ghidra)
    if (has_ghidra) {
        if (!validate_headless_args(args)) {
            return 1;
        }
        // --mcp is a serving action too: like --http it keeps the process alive
        // serving an endpoint, so it follows the same serve-mode rules and runs
        // via the live server path (which now starts HTTP and/or MCP).
        const bool headless_serve = args.serve || args.mcp;
        if (headless_serve && (!args.query.empty() || !args.sql_file.empty() || args.interactive)) {
            std::cerr << "headless serve mode (--http/--mcp) cannot be combined with -q/-f/-i\n";
            return 1;
        }
        // Serve mode is meant to run until explicitly stopped (Ctrl-C or
        // POST /shutdown), so it should not inherit the one-shot safety cap.
        // The 600s default is a runaway-process backstop for -q/-f/REPL runs;
        // for a long-lived server it would silently kill the Ghidra host out
        // from under the still-listening front door. Default serve mode
        // to no cap unless the user asked for one explicitly.
        if (headless_serve && !args.max_runtime_explicit) {
            args.max_runtime = 0;
        }
        if (headless_serve) {
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

    // Connect mode (--url). --http/--mcp are serving actions here too: they keep
    // the process alive on an endpoint, so (mirroring headless) they cannot be
    // combined with a one-shot action that runs and exits — otherwise the server
    // would start, the one-shot would run, and the process would exit while the
    // listener was still bound. Also reject port collisions before binding.
    const bool connect_serve = args.serve || args.mcp;
    if (connect_serve && (!args.query.empty() || !args.sql_file.empty() || args.interactive)) {
        std::cerr << "serve mode (--http/--mcp) cannot be combined with -q/-f/-i\n";
        return 1;
    }
    if (!validate_server_ports(args, /*rpc_active=*/false)) {
        return 1;
    }

    std::shared_ptr<ghidrasql::Source> source;
    ghidrasql::LibGhidraSourceOptions opts;
    opts.base_url = args.url;
    opts.auth_token = args.auth_token;

    const std::string selected_program = selected_program_arg(args);

    // Auto-open when --project + --program are both set.
    const bool has_open_params = !args.project.empty() && !selected_program.empty();
    opts.auto_open_program = has_open_params;
    opts.project_path = args.project;
    opts.project_name = args.project_name;
    opts.program_path = selected_program;
    // Connect mode attaches to a program that is normally already open and
    // analyzed in the host, so — unlike headless, which default-analyzes
    // (args.analyze defaults to true) — it re-runs analysis on auto-open ONLY
    // when the user asked for it explicitly (`--analyze`/`--no-analyze` set
    // args.analyze_explicit). This intentional asymmetry avoids re-analyzing an
    // already-analyzed attached program by default.
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
    // One shared mutex serializes ALL engine access in connect serve mode. The
    // QueryEngine is not concurrency-safe, so concurrent HTTP requests (httplib
    // worker threads) and the MCP server thread must take the same lock — mirrors
    // headless mode's session_mu. Declared before `http` so it outlives the
    // server whose worker threads use it.
    std::mutex session_mu;
    ghidrasql::HttpServer http;

    ghidrasql::HttpServer::Options http_options;
    http_options.port = args.port;
    http_options.bind_address = args.bind;
    http_options.auth_token = args.auth_token;

    if (args.serve) {
        int started_port = http.start(
            [&](const std::string& sql, const xsql::ScriptOptions& opts) {
                std::lock_guard<std::mutex> lock(session_mu);
                return engine.run_script(sql, opts);
            },
            [&]() {
                std::lock_guard<std::mutex> lock(session_mu);
                return engine.info();
            },
            http_options,
            [&]() {
                std::lock_guard<std::mutex> lock(session_mu);
                return engine.refresh();
            });
        if (started_port <= 0) {
            std::cerr << "failed to start HTTP server\n";
            return 1;
        }
        std::cout << "HTTP started at " << http.url() << "\n";
    }

#ifdef GHIDRASQL_HAS_MCP
    std::unique_ptr<ghidrasql::GhidrasqlMcpServer> mcp_server;
    if (args.mcp) {
        mcp_server = std::make_unique<ghidrasql::GhidrasqlMcpServer>();
        int started = mcp_server->start(args.mcp_port,
            [&engine, &session_mu](const std::string& sql,
                                   bool continue_on_error,
                                   bool include_sql) {
                std::lock_guard<std::mutex> lk(session_mu);
                xsql::ScriptOptions opts;
                opts.continue_on_error = continue_on_error;
                opts.include_sql = include_sql;
                auto script = ghidrasql::run_script(engine, sql, opts);
                return xsql::script_result_to_json(script, opts.include_sql);
            },
            args.bind,
            args.auth_token);
        if (started <= 0) {
            std::cerr << "failed to start MCP server\n";
            return 1;
        }
        std::cout << ghidrasql::format_mcp_info(started, args.bind);
    }
#else
    if (args.mcp) {
        std::cerr << "MCP not available in this build "
                     "(rebuild with -DGHIDRASQL_WITH_MCP=ON)\n";
        return 1;
    }
#endif

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

    // --mcp is a serving action: an --mcp run (with or without --http) must keep
    // the process alive rather than fall through to the REPL and exit on EOF.
    const bool serving = args.serve || args.mcp;
    const bool repl = args.interactive || (!serving && args.query.empty() && args.sql_file.empty());
    if (!repl) {
        // Serve until Ctrl-C / shutdown. HTTP can self-stop (POST /shutdown); an
        // MCP-only server has no such endpoint, so it runs until signaled. An
        // explicit --max-runtime caps this loop too — the flag's contract is
        // "caps the whole process", connect mode included.
        const bool have_runtime_cap = args.max_runtime_explicit && args.max_runtime > 0;
        const auto serve_deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(args.max_runtime);
        while (!g_stop.load()) {
            if (args.serve && !http.is_running()) {
                break;
            }
            if (have_runtime_cap &&
                std::chrono::steady_clock::now() >= serve_deadline) {
                std::cout << "max-runtime (" << args.max_runtime
                          << "s) reached; shutting down\n"
                          << std::flush;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        http.stop();
        return 0;
    }

    return run_repl(engine, source, http, http_options, args.format);
}
