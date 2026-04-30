// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <xsql/database.hpp>

namespace ghidrasql {
class Source;

namespace functions {

std::string to_hex(std::int64_t value);
std::string normalize_text(std::string text);
std::vector<std::string> tokenize(const std::string& normalized);
bool all_query_terms_match(const std::string& haystack_norm, const std::string& query_norm);
double query_score(const std::string& haystack_norm, const std::string& query_norm);
std::string lower_ascii(std::string text);
std::string squash_ws(std::string text);
double search_domain_weight(const std::string& domain);
std::string search_snippet(const std::string& text, const std::string& query, std::int64_t radius);
std::string join_tokens(const std::vector<std::string>& tokens);
std::string type_strip_cv(const std::string& decl);
bool type_is_pointer(const std::string& decl);
std::string type_family(const std::string& decl);

void register_sql_functions(xsql::Database& db, Source& source);

}  // namespace functions
}  // namespace ghidrasql