// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "internal/functions.hpp"

#include <ghidrasql/source.hpp>
#include <xsql/database.hpp>
#include <xsql/functions.hpp>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace ghidrasql::functions {

std::string to_hex(std::int64_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::uppercase << static_cast<unsigned long long>(value);
    return out.str();
}

std::string normalize_text(std::string text) {
    for (char& ch : text) {
        unsigned char uc = static_cast<unsigned char>(ch);
        if (std::isalnum(uc) != 0) {
            ch = static_cast<char>(std::tolower(uc));
        } else {
            ch = ' ';
        }
    }
    std::string out;
    out.reserve(text.size());
    bool prev_space = true;
    for (char ch : text) {
        if (ch == ' ') {
            if (!prev_space) {
                out.push_back(' ');
            }
            prev_space = true;
        } else {
            out.push_back(ch);
            prev_space = false;
        }
    }
    if (!out.empty() && out.back() == ' ') {
        out.pop_back();
    }
    return out;
}

std::vector<std::string> tokenize(const std::string& normalized) {
    std::vector<std::string> out;
    std::string cur;
    for (char ch : normalized) {
        if (ch == ' ') {
            if (!cur.empty()) {
                out.push_back(cur);
                cur.clear();
            }
            continue;
        }
        cur.push_back(ch);
    }
    if (!cur.empty()) {
        out.push_back(cur);
    }
    return out;
}

bool all_query_terms_match(const std::string& haystack_norm, const std::string& query_norm) {
    const auto terms = tokenize(query_norm);
    if (terms.empty()) {
        return false;
    }
    for (const auto& term : terms) {
        if (haystack_norm.find(term) == std::string::npos) {
            return false;
        }
    }
    return true;
}

double query_score(const std::string& haystack_norm, const std::string& query_norm) {
    const auto terms = tokenize(query_norm);
    if (terms.empty()) {
        return 0.0;
    }

    double score = 0.0;
    for (const auto& term : terms) {
        size_t pos = 0;
        std::int64_t count = 0;
        while (pos < haystack_norm.size()) {
            pos = haystack_norm.find(term, pos);
            if (pos == std::string::npos) {
                break;
            }
            ++count;
            pos += term.size();
        }
        score += static_cast<double>(count);
    }
    if (!query_norm.empty() && haystack_norm.find(query_norm) != std::string::npos) {
        score += 5.0;
    }
    if (!query_norm.empty() && haystack_norm.rfind(query_norm, 0) == 0) {
        score += 2.0;
    }
    return score;
}

std::string lower_ascii(std::string text) {
    for (char& ch : text) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return text;
}

std::string squash_ws(std::string text) {
    for (char& ch : text) {
        if (std::isspace(static_cast<unsigned char>(ch)) != 0) {
            ch = ' ';
        }
    }
    std::string out;
    out.reserve(text.size());
    bool prev_space = true;
    for (char ch : text) {
        if (ch == ' ') {
            if (!prev_space) {
                out.push_back(' ');
            }
            prev_space = true;
        } else {
            out.push_back(ch);
            prev_space = false;
        }
    }
    if (!out.empty() && out.back() == ' ') {
        out.pop_back();
    }
    return out;
}

double search_domain_weight(const std::string& domain) {
    const std::string d = normalize_text(domain);
    if (d == "function" || d == "symbol" || d == "signature") {
        return 3.0;
    }
    if (d == "string" || d == "comment") {
        return 2.0;
    }
    if (d == "type") {
        return 1.5;
    }
    return 1.0;
}

std::string search_snippet(const std::string& text, const std::string& query, std::int64_t radius) {
    if (text.empty()) {
        return {};
    }
    if (radius < 8) {
        radius = 8;
    }
    if (radius > 512) {
        radius = 512;
    }

    const std::string cleaned = squash_ws(text);
    const std::string query_norm = normalize_text(query);
    const auto terms = tokenize(query_norm);
    const std::string haystack_lower = lower_ascii(cleaned);

    size_t hit_pos = std::string::npos;
    size_t hit_len = 0;
    for (const auto& term : terms) {
        if (term.empty()) {
            continue;
        }
        const size_t pos = haystack_lower.find(term);
        if (pos == std::string::npos) {
            continue;
        }
        if (hit_pos == std::string::npos || pos < hit_pos) {
            hit_pos = pos;
            hit_len = term.size();
        }
    }

    if (hit_pos == std::string::npos) {
        const size_t cap = static_cast<size_t>(std::min<std::int64_t>(radius * 2, static_cast<std::int64_t>(cleaned.size())));
        if (cap == cleaned.size()) {
            return cleaned;
        }
        return cleaned.substr(0, cap) + "...";
    }

    size_t start = hit_pos > static_cast<size_t>(radius) ? hit_pos - static_cast<size_t>(radius) : 0;
    size_t end = std::min(cleaned.size(), hit_pos + hit_len + static_cast<size_t>(radius));
    std::string out = cleaned.substr(start, end - start);
    if (start > 0) {
        out = "..." + out;
    }
    if (end < cleaned.size()) {
        out += "...";
    }
    return out;
}

std::string join_tokens(const std::vector<std::string>& tokens) {
    std::string out;
    for (const auto& tok : tokens) {
        if (tok.empty()) {
            continue;
        }
        if (!out.empty()) {
            out.push_back(' ');
        }
        out += tok;
    }
    return out;
}

std::string type_strip_cv(const std::string& decl) {
    const std::string norm = normalize_text(decl);
    auto tokens = tokenize(norm);
    const std::unordered_set<std::string> cv = {"const", "volatile", "restrict", "mutable"};

    std::vector<std::string> filtered;
    filtered.reserve(tokens.size());
    for (const auto& t : tokens) {
        if (cv.find(t) == cv.end()) {
            filtered.push_back(t);
        }
    }

    std::string out = join_tokens(filtered);
    const auto ptr_count = static_cast<int>(std::count(decl.begin(), decl.end(), '*'));
    const auto ref_count = static_cast<int>(std::count(decl.begin(), decl.end(), '&'));
    for (int i = 0; i < std::min(ptr_count, 4); ++i) {
        if (!out.empty()) {
            out.push_back(' ');
        }
        out.push_back('*');
    }
    for (int i = 0; i < std::min(ref_count, 4); ++i) {
        if (!out.empty()) {
            out.push_back(' ');
        }
        out.push_back('&');
    }
    if (out.empty()) {
        out = norm;
    }
    return out;
}

bool type_is_pointer(const std::string& decl) {
    if (decl.find('*') != std::string::npos || decl.find('&') != std::string::npos) {
        return true;
    }
    const auto tokens = tokenize(normalize_text(decl));
    for (const auto& t : tokens) {
        if (t == "ptr" || t == "pointer" || t == "ref" || t == "reference") {
            return true;
        }
    }
    return false;
}

std::string type_family(const std::string& decl) {
    const std::string norm = normalize_text(decl);
    const auto tokens = tokenize(norm);
    const std::unordered_set<std::string> token_set(tokens.begin(), tokens.end());

    if (token_set.find("struct") != token_set.end() ||
        token_set.find("class") != token_set.end() ||
        token_set.find("union") != token_set.end()) {
        return "aggregate";
    }
    if (token_set.find("enum") != token_set.end()) {
        return "enum";
    }
    if (token_set.find("typedef") != token_set.end() || token_set.find("using") != token_set.end()) {
        return "alias";
    }
    if (decl.find('(') != std::string::npos && decl.find(')') != std::string::npos) {
        return "function";
    }
    if (type_is_pointer(decl)) {
        return "pointer";
    }
    if (token_set.find("bool") != token_set.end()) {
        return "boolean";
    }
    if (token_set.find("float") != token_set.end() || token_set.find("double") != token_set.end()) {
        return "floating";
    }
    if (token_set.find("char") != token_set.end() ||
        token_set.find("short") != token_set.end() ||
        token_set.find("int") != token_set.end() ||
        token_set.find("long") != token_set.end() ||
        token_set.find("size_t") != token_set.end() ||
        token_set.find("ssize_t") != token_set.end() ||
        token_set.find("unsigned") != token_set.end() ||
        token_set.find("signed") != token_set.end() ||
        token_set.find("uint8_t") != token_set.end() ||
        token_set.find("uint16_t") != token_set.end() ||
        token_set.find("uint32_t") != token_set.end() ||
        token_set.find("uint64_t") != token_set.end() ||
        token_set.find("int8_t") != token_set.end() ||
        token_set.find("int16_t") != token_set.end() ||
        token_set.find("int32_t") != token_set.end() ||
        token_set.find("int64_t") != token_set.end()) {
        return "integral";
    }
    if (token_set.find("void") != token_set.end()) {
        return "void";
    }
    return "unknown";
}

void register_sql_functions(xsql::Database& db, Source& source) {
    db.register_function("hex", 1, [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 1 || argv[0].is_null()) {
            ctx.result_null();
            return;
        }
        ctx.result_text(to_hex(argv[0].as_int64()));
    });

    db.register_function("decompile", 1, [&source](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 1 || argv[0].is_null()) {
            ctx.result_null();
            return;
        }
        std::string result = source.decompile(argv[0].as_int64());
        if (result.empty()) {
            ctx.result_null();
            return;
        }
        ctx.result_text(result);
    });

    db.register_function("normalize_text", 1, [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 1 || argv[0].is_null()) {
            ctx.result_null();
            return;
        }
        ctx.result_text(normalize_text(argv[0].as_text()));
    });

    db.register_function("search_match", 2, [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
            ctx.result_int(0);
            return;
        }
        const std::string haystack = normalize_text(argv[0].as_text());
        const std::string query = normalize_text(argv[1].as_text());
        ctx.result_int(all_query_terms_match(haystack, query) ? 1 : 0);
    });

    db.register_function("search_score", 2, [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
            ctx.result_double(0.0);
            return;
        }
        const std::string haystack = normalize_text(argv[0].as_text());
        const std::string query = normalize_text(argv[1].as_text());
        ctx.result_double(query_score(haystack, query));
    });

    db.register_function("search_snippet", 2, [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 2 || argv[0].is_null() || argv[1].is_null()) {
            ctx.result_null();
            return;
        }
        const std::string snippet = search_snippet(argv[0].as_text(), argv[1].as_text(), 48);
        if (snippet.empty()) {
            ctx.result_null();
            return;
        }
        ctx.result_text(snippet);
    });

    db.register_function("search_snippet", 3, [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 3 || argv[0].is_null() || argv[1].is_null()) {
            ctx.result_null();
            return;
        }
        const std::int64_t radius = argv[2].is_null() ? 48 : argv[2].as_int64();
        const std::string snippet = search_snippet(argv[0].as_text(), argv[1].as_text(), radius);
        if (snippet.empty()) {
            ctx.result_null();
            return;
        }
        ctx.result_text(snippet);
    });

    db.register_function("search_rank", 3, [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 3 || argv[0].is_null() || argv[1].is_null() || argv[2].is_null()) {
            ctx.result_double(0.0);
            return;
        }
        const std::string domain = argv[0].as_text();
        const std::string haystack = normalize_text(argv[1].as_text());
        const std::string query = normalize_text(argv[2].as_text());
        const double score = query_score(haystack, query) * search_domain_weight(domain);
        ctx.result_double(score);
    });

    db.register_function("type_family", 1, [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 1 || argv[0].is_null()) {
            ctx.result_null();
            return;
        }
        ctx.result_text(type_family(argv[0].as_text()));
    });

    db.register_function("type_is_pointer", 1, [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 1 || argv[0].is_null()) {
            ctx.result_int(0);
            return;
        }
        ctx.result_int(type_is_pointer(argv[0].as_text()) ? 1 : 0);
    });

    db.register_function("type_strip_cv", 1, [](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 1 || argv[0].is_null()) {
            ctx.result_null();
            return;
        }
        ctx.result_text(type_strip_cv(argv[0].as_text()));
    });

    db.register_function("string_count", 0, [&source](xsql::FunctionContext& ctx, int, xsql::FunctionArg*) {
        std::vector<model::StringRow> rows;
        if (!source.read_strings(rows)) {
            ctx.result_int64(0);
            return;
        }
        ctx.result_int64(static_cast<std::int64_t>(rows.size()));
    });

    db.register_function("rebuild_strings", 0, [&source](xsql::FunctionContext& ctx, int, xsql::FunctionArg*) {
        source.refresh();
        std::vector<model::StringRow> rows;
        if (!source.read_strings(rows)) {
            ctx.result_int64(0);
            return;
        }
        ctx.result_int64(static_cast<std::int64_t>(rows.size()));
    });

    db.register_function("program_revision", 0, [&source](xsql::FunctionContext& ctx, int, xsql::FunctionArg*) {
        model::ProgramInfoRow info;
        if (!source.read_program_info(info)) {
            ctx.result_int64(0);
            return;
        }
        ctx.result_int64(info.revision);
    });

    db.register_function("save_database", 0, [&source](xsql::FunctionContext& ctx, int, xsql::FunctionArg*) {
        ctx.result_int(source.save_database() ? 1 : 0);
    });

    db.register_function("discard_changes", 0, [&source](xsql::FunctionContext& ctx, int, xsql::FunctionArg*) {
        ctx.result_int(source.discard_changes() ? 1 : 0);
    });

    db.register_function("refresh_database", 0, [&source](xsql::FunctionContext& ctx, int, xsql::FunctionArg*) {
        ctx.result_int(source.refresh() ? 1 : 0);
    });

    db.register_function("rename_local", 3, [&source](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 3 || argv[0].is_null() || argv[1].is_null() || argv[2].is_null()) {
            ctx.result_int(0);
            return;
        }
        const std::int64_t func_addr = argv[0].as_int64();
        const std::string local_id = argv[1].as_text();
        const std::string new_name = argv[2].as_text();
        if (local_id.empty() || new_name.empty()) {
            ctx.result_int(0);
            return;
        }
        ctx.result_int(source.rename_decomp_local(func_addr, local_id, new_name) ? 1 : 0);
    });

    db.register_function("parse_decls", 1, [&source](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 1 || argv[0].is_null()) {
            ctx.result_int(-1);
            return;
        }
        const std::string source_text = argv[0].as_text();
        if (source_text.empty()) {
            ctx.result_int(0);
            return;
        }
        ctx.result_int(source.parse_declarations(source_text));
    });

    db.register_function("set_local_type", 3, [&source](xsql::FunctionContext& ctx, int argc, xsql::FunctionArg* argv) {
        if (argc < 3 || argv[0].is_null() || argv[1].is_null() || argv[2].is_null()) {
            ctx.result_int(0);
            return;
        }
        const std::int64_t func_addr = argv[0].as_int64();
        const std::string local_id = argv[1].as_text();
        const std::string new_type = argv[2].as_text();
        if (local_id.empty() || new_type.empty()) {
            ctx.result_int(0);
            return;
        }
        ctx.result_int(source.set_decomp_local_type(func_addr, local_id, new_type) ? 1 : 0);
    });
}

}  // namespace ghidrasql::functions
