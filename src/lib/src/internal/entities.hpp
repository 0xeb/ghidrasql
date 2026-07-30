// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include <xsql/database.hpp>

namespace xsql::runtime {
class RuntimeSettingsCore;
}

namespace ghidrasql {
class Source;

namespace entities {

std::int64_t stable_type_ordinal(const std::string& type_id);

class TableRegistry {
public:
    // `settings` backs the writable `runtime_settings` table (a live view over
    // the runtime controls). May be null (tests that only exercise data tables);
    // the table then reports the shared-core defaults and rejects writes.
    explicit TableRegistry(
        std::shared_ptr<Source> source,
        std::shared_ptr<xsql::runtime::RuntimeSettingsCore> settings = nullptr);
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

