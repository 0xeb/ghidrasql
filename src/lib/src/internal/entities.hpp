// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include <xsql/database.hpp>

namespace ghidrasql {
class Source;

namespace entities {

std::int64_t stable_type_ordinal(const std::string& type_id);

class TableRegistry {
public:
    explicit TableRegistry(std::shared_ptr<Source> source);
    ~TableRegistry();

    TableRegistry(const TableRegistry&) = delete;
    TableRegistry& operator=(const TableRegistry&) = delete;
    TableRegistry(TableRegistry&&) noexcept;
    TableRegistry& operator=(TableRegistry&&) noexcept;

    void register_all(xsql::Database& db);
    void invalidate_all() const;
    bool invalidate_table(const std::string& name) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace entities
}  // namespace ghidrasql

