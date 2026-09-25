// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

// Small, pure request-body helpers shared by the CLI's HTTP project-control
// handlers. Kept header-only so they can be unit-tested without the CLI binary.

#include <xsql/json.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

namespace ghidrasql::cli {

inline std::string trim_copy(std::string value) {
    auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](unsigned char ch) {
        return !is_space(ch);
    }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [&](unsigned char ch) {
        return !is_space(ch);
    }).base(), value.end());
    return value;
}

// Extract a string value from a request body that may be either a raw string
// (the value itself) or a JSON object carrying it under `key` (or `alternate_key`).
//
// Returns:
//   - the keyed string, when the body is a JSON object with that key;
//   - the trimmed body, when the body is NOT a JSON object (a raw path/string);
//   - empty, when the body is a JSON object that LACKS the key (so callers emit
//     a clean "<key> is required" instead of treating the whole JSON blob as the
//     value).
inline std::string string_from_json_or_raw(
    const std::string& body,
    const std::string& key,
    const std::string& alternate_key = {})
{
    const std::string trimmed = trim_copy(body);
    if (trimmed.empty()) {
        return {};
    }
    try {
        auto j = xsql::json::parse(trimmed);
        if (j.is_object()) {
            if (j.contains(key) && j[key].is_string()) {
                return j[key].get<std::string>();
            }
            if (!alternate_key.empty() && j.contains(alternate_key) && j[alternate_key].is_string()) {
                return j[alternate_key].get<std::string>();
            }
            // Parsed as a JSON object but the requested key is absent: do NOT
            // fall back to the raw body — that would treat the whole JSON blob
            // as a path. Return empty so callers emit a clean "<key> is required".
            return {};
        }
    } catch (...) {
    }
    return trimmed;
}

// Loader arguments for a --binary import. Off by default (LibGhidraHost skips
// external system libraries during import); load_libraries re-enables the
// loader's ordinal lookup + library load/link. This is the SINGLE source of
// truth for BOTH import sites — the headless startup import
// (import_programs_and_open_active) and the HTTP /project/import handler
// (run_headless_live_server) — so the two can never drift apart.
//
// Templated on the name/value pair type (aggregate-initialized {name, value})
// so this header stays libghidra-free and unit-testable without the CLI binary;
// call sites instantiate it with libghidra::client::LoaderArg.
// Split a comma-separated analyzer pattern list ("Objective-C, Shared Return") into
// trimmed, non-empty patterns. Used by --analyzers-off/--analyzers-on.
inline std::vector<std::string> split_pattern_list(const std::string& value) {
    std::vector<std::string> out;
    std::string current;
    for (char c : value) {
        if (c == ',') {
            current = trim_copy(current);
            if (!current.empty()) {
                out.push_back(current);
            }
            current.clear();
            continue;
        }
        current.push_back(c);
    }
    current = trim_copy(current);
    if (!current.empty()) {
        out.push_back(current);
    }
    return out;
}

// Analyzer patterns for an import request body: a JSON array of strings, or one
// comma-separated string, under `key`; `fallback` (the CLI flags) when absent or
// malformed. The SINGLE source of truth for the HTTP /project/import handler, so a
// body that omits the key keeps the startup --analyzers-off/--analyzers-on policy.
inline std::vector<std::string> patterns_from_json(
    const std::string& body,
    const std::string& key,
    const std::vector<std::string>& fallback)
{
    try {
        auto j = xsql::json::parse(body);
        if (j.is_object() && j.contains(key)) {
            const auto& value = j[key];
            if (value.is_string()) {
                return split_pattern_list(value.get<std::string>());
            }
            if (value.is_array()) {
                std::vector<std::string> out;
                for (const auto& item : value) {
                    if (!item.is_string()) {
                        return fallback;
                    }
                    std::string pattern = trim_copy(item.get<std::string>());
                    if (!pattern.empty()) {
                        out.push_back(pattern);
                    }
                }
                return out;
            }
        }
    } catch (...) {
    }
    return fallback;
}

template <typename LoaderArgT>
std::vector<LoaderArgT> import_loader_args(bool load_libraries) {
    if (!load_libraries) {
        return {};
    }
    return {
        LoaderArgT{"-loader-ordinalLookup", "true"},
        LoaderArgT{"-loader-linkExistingProjectLibraries", "true"},
        LoaderArgT{"-loader-loadLibraries", "true"},
    };
}

} // namespace ghidrasql::cli
