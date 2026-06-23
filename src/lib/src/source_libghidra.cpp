// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include <ghidrasql/source.hpp>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>

#ifdef GHIDRASQL_HAS_LIBGHIDRA
#include <libghidra/http.hpp>
#include <xsql/vtable.hpp>
#endif

namespace ghidrasql {

#ifdef GHIDRASQL_HAS_LIBGHIDRA
class LibGhidraSource final : public Source {
public:
    static constexpr std::uint64_t kAllAddressesMin = 0;
    // Use INT64_MAX, not UINT64_MAX: the LibGhidraHost decodes the protobuf uint64 range
    // end into a signed Java long, so UINT64_MAX arrives as -1 and trips a getMaxAddress()
    // fallback that empties range-filtered tables for programs with EXTERNAL/low-offset
    // spaces. A large positive sentinel stays positive on the host. See ghidrasql #2/#3/#6.
    static constexpr std::uint64_t kAllAddressesMax =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());

    explicit LibGhidraSource(LibGhidraSourceOptions options)
        : options_(std::move(options)),
          client_(make_http_client_options(options_)) {}

private:
    static libghidra::client::HttpClientOptions
    make_http_client_options(const LibGhidraSourceOptions& opts) {
        libghidra::client::HttpClientOptions out{opts.base_url, opts.auth_token};
        if (opts.read_timeout_ms > 0) {
            out.read_timeout = std::chrono::milliseconds(opts.read_timeout_ms);
        }
        return out;
    }

public:

    std::string last_error() const override {
        std::lock_guard<std::mutex> lock(mu_);
        return last_error_;
    }

    bool read_project_files(std::vector<model::ProjectFileRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_project_open_locked()) return false;
        libghidra::client::ListProjectFilesRequest req;
        req.include_folders = true;
        auto listed = client_.ListProjectFiles(req);
        if (!ok_or_record_error_locked(listed, "ListProjectFiles")) return false;
        out.reserve(listed.value->files.size());
        for (const auto& row : listed.value->files) {
            model::ProjectFileRow mapped;
            mapped.path = row.path;
            mapped.name = row.name;
            mapped.folder_path = row.folder_path;
            mapped.content_type = row.content_type;
            mapped.domain_object_class = row.domain_object_class;
            mapped.is_folder = row.is_folder ? 1 : 0;
            mapped.is_program = row.is_program ? 1 : 0;
            out.push_back(std::move(mapped));
        }
        last_error_.clear();
        return true;
    }

    bool read_functions(std::vector<model::FunctionRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            trace_rpc_locked("ListFunctions");
            auto listed = client_.ListFunctions(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListFunctions")) return false;
            const auto& rows = listed.value->functions;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                dest.push_back(map_function(row));
            }
            return true;
        });
    }

    bool read_function_at(std::int64_t address, model::FunctionRow& out) const override {
        out = {};
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        trace_rpc_locked("GetFunction");
        auto got = client_.GetFunction(to_u64(address));
        if (!ok_or_record_error_locked(got, "GetFunction")) return false;
        if (!got.value->function.has_value()) {
            last_error_.clear();
            return false;
        }
        out = map_function(*got.value->function);
        last_error_.clear();
        return true;
    }

    bool read_segments(std::vector<model::SegmentRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        int bitness = derive_bitness_locked();
        return paginate_locked(256, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListMemoryBlocks(ps, off);
            if (!ok_or_record_error_locked(listed, "ListMemoryBlocks")) return false;
            const auto& rows = listed.value->blocks;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::SegmentRow mapped;
                mapped.start_ea = to_i64(row.start_address);
                mapped.end_ea = to_i64(row.end_address);
                mapped.name = row.name;
                mapped.segment_class = row.is_execute ? "CODE" : "DATA";
                mapped.perm = (row.is_read ? 4 : 0) | (row.is_write ? 2 : 0) | (row.is_execute ? 1 : 0);
                mapped.bitness = bitness;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_memory_blocks(std::vector<model::MemoryBlockRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        int bitness = derive_bitness_locked();
        return paginate_locked(256, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListMemoryBlocks(ps, off);
            if (!ok_or_record_error_locked(listed, "ListMemoryBlocks")) return false;
            const auto& rows = listed.value->blocks;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::MemoryBlockRow mapped;
                mapped.start_ea = to_i64(row.start_address);
                mapped.end_ea = to_i64(row.end_address);
                mapped.name = row.name;
                mapped.block_class = row.is_execute ? "CODE" : "DATA";
                mapped.perm = (row.is_read ? 4 : 0) | (row.is_write ? 2 : 0) | (row.is_execute ? 1 : 0);
                mapped.bitness = bitness;
                mapped.size = to_i64(row.size);
                mapped.is_read = row.is_read ? 1 : 0;
                mapped.is_write = row.is_write ? 1 : 0;
                mapped.is_exec = row.is_execute ? 1 : 0;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_imports(std::vector<model::ImportRow>& out) const override {
        out.clear();
        std::vector<model::SymbolRow> symbols;
        if (!read_symbols(symbols)) {
            return false;
        }
        out.reserve(symbols.size());
        for (const auto& sym : symbols) {
            if (!sym.is_external) {
                continue;
            }
            model::ImportRow row;
            row.address = sym.address;
            row.name = sym.name;
            row.module = sym.namespace_name.empty() ? "external" : sym.namespace_name;
            out.push_back(std::move(row));
        }
        return true;
    }

    bool read_exports(std::vector<model::ExportRow>& out) const override {
        out.clear();
        std::vector<model::SymbolRow> symbols;
        if (!read_symbols(symbols)) {
            return false;
        }
        out.reserve(symbols.size());
        for (const auto& sym : symbols) {
            if (sym.is_external || !sym.is_primary) {
                continue;
            }
            model::ExportRow row;
            row.address = sym.address;
            row.name = sym.name;
            row.module = sym.namespace_name.empty() ? "" : sym.namespace_name;
            out.push_back(std::move(row));
        }
        return true;
    }

    bool read_strings(std::vector<model::StringRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListDefinedStrings(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListDefinedStrings")) return false;
            const auto& rows = listed.value->strings;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                dest.push_back(map_string(row));
            }
            return true;
        });
    }

    bool read_strings_at(std::int64_t address, std::vector<model::StringRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(64, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListDefinedStrings(to_u64(address), to_u64(address), ps, off);
            if (!ok_or_record_error_locked(listed, "ListDefinedStrings")) return false;
            const auto& rows = listed.value->strings;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                if (to_i64(row.address) == address) {
                    dest.push_back(map_string(row));
                }
            }
            return true;
        });
    }

    bool read_call_edges(std::vector<model::CallEdgeRow>& out) const override {
        out.clear();
        std::vector<model::FunctionRow> functions;
        std::vector<model::XrefRow> xrefs;
        if (!read_functions(functions) || !read_xrefs(xrefs)) {
            return false;
        }

        // Sort functions by address for binary search
        std::sort(functions.begin(), functions.end(), [](const auto& a, const auto& b) {
            return a.address < b.address;
        });

        auto find_owner = [&](std::int64_t ea) -> std::int64_t {
            // Find first function with address > ea
            auto it = std::upper_bound(functions.begin(), functions.end(), ea,
                [](std::int64_t addr, const model::FunctionRow& fn) { return addr < fn.address; });
            if (it != functions.begin()) {
                --it;
                const std::int64_t fn_end = it->end_ea > it->address
                    ? it->end_ea : (it->address + std::max<std::int64_t>(it->size, 1));
                if (ea >= it->address && ea < fn_end) {
                    return it->address;
                }
            }
            return 0;
        };
        auto is_call_like = [](const std::string& kind) {
            std::string lowered = kind;
            std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            return lowered.find("call") != std::string::npos;
        };

        out.reserve(xrefs.size());
        for (const auto& xref : xrefs) {
            if (!is_call_like(xref.kind)) {
                continue;
            }
            model::CallEdgeRow row;
            row.src_func_addr = find_owner(xref.from_ea);
            row.call_site = xref.from_ea;
            row.dst_addr = xref.to_ea;
            row.dst_func_addr = find_owner(xref.to_ea);
            row.kind = xref.kind;
            out.push_back(std::move(row));
        }
        return true;
    }

    bool read_function_calls(std::vector<model::FunctionCallRow>& out) const override {
        out.clear();
        std::vector<model::FunctionRow> functions;
        std::vector<model::CallEdgeRow> edges;
        if (!read_functions(functions) || !read_call_edges(edges)) {
            return false;
        }

        // Sort functions by address for binary search
        std::sort(functions.begin(), functions.end(), [](const auto& a, const auto& b) {
            return a.address < b.address;
        });

        auto func_name = [&](std::int64_t func_addr) -> std::string {
            auto it = std::lower_bound(functions.begin(), functions.end(), func_addr,
                [](const model::FunctionRow& fn, std::int64_t addr) { return fn.address < addr; });
            if (it != functions.end() && it->address == func_addr) {
                return it->name;
            }
            return std::string{};
        };

        for (const auto& edge : edges) {
            auto existing = std::find_if(out.begin(), out.end(), [&](const model::FunctionCallRow& row) {
                return row.src_func_addr == edge.src_func_addr && row.dst_func_addr == edge.dst_func_addr;
            });
            if (existing == out.end()) {
                model::FunctionCallRow row;
                row.src_func_addr = edge.src_func_addr;
                row.src_func_name = func_name(edge.src_func_addr);
                row.dst_func_addr = edge.dst_func_addr;
                row.dst_func_name = func_name(edge.dst_func_addr);
                row.edge_count = 1;
                out.push_back(std::move(row));
            } else {
                existing->edge_count += 1;
            }
        }
        return true;
    }

    bool read_blocks(std::vector<model::BlockRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListBasicBlocks(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListBasicBlocks")) return false;
            const auto& rows = listed.value->blocks;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::BlockRow mapped;
                mapped.func_addr = to_i64(row.function_entry);
                mapped.start_ea = to_i64(row.start_address);
                mapped.end_ea = to_i64(row.end_address);
                mapped.in_degree = static_cast<int>(row.in_degree);
                mapped.out_degree = static_cast<int>(row.out_degree);
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_cfg_edges(std::vector<model::CfgEdgeRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListCFGEdges(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListCFGEdges")) return false;
            const auto& rows = listed.value->edges;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::CfgEdgeRow mapped;
                mapped.func_addr = to_i64(row.function_entry);
                mapped.src_start_ea = to_i64(row.src_block_start);
                mapped.dst_start_ea = to_i64(row.dst_block_start);
                mapped.edge_kind = row.edge_kind;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_switch_tables(std::vector<model::SwitchTableRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListSwitchTables(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListSwitchTables")) return false;
            const auto& rows = listed.value->switch_tables;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::SwitchTableRow mapped;
                mapped.func_addr = to_i64(row.function_entry);
                mapped.instr_ea = to_i64(row.switch_address);
                mapped.case_count = static_cast<std::int64_t>(row.case_count);
                mapped.default_ea = to_i64(row.default_address);
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_dominators(std::vector<model::DominatorRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListDominators(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListDominators")) return false;
            const auto& rows = listed.value->dominators;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::DominatorRow mapped;
                mapped.func_addr = to_i64(row.function_entry);
                mapped.node_ea = to_i64(row.block_address);
                mapped.idom_ea = to_i64(row.idom_address);
                mapped.depth = static_cast<int>(row.depth);
                mapped.is_entry = row.is_entry ? 1 : 0;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_post_dominators(std::vector<model::PostDominatorRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListPostDominators(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListPostDominators")) return false;
            const auto& rows = listed.value->post_dominators;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::PostDominatorRow mapped;
                mapped.func_addr = to_i64(row.function_entry);
                mapped.node_ea = to_i64(row.block_address);
                mapped.ipdom_ea = to_i64(row.ipdom_address);
                mapped.depth = static_cast<int>(row.depth);
                mapped.is_exit = row.is_exit ? 1 : 0;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_loops(std::vector<model::LoopRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListLoops(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListLoops")) return false;
            const auto& rows = listed.value->loops;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::LoopRow mapped;
                mapped.func_addr = to_i64(row.function_entry);
                mapped.header_ea = to_i64(row.header_address);
                mapped.latch_ea = to_i64(row.back_edge_source);
                mapped.loop_kind = row.loop_kind;
                mapped.block_count = static_cast<std::int64_t>(row.block_count);
                mapped.depth = static_cast<int>(row.depth);
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_data_items(std::vector<model::DataItemRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListDataItems(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListDataItems")) return false;
            const auto& rows = listed.value->data_items;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                dest.push_back(map_data_item(row));
            }
            return true;
        });
    }

    bool read_data_items_at(std::int64_t address, std::vector<model::DataItemRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(64, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListDataItems(to_u64(address), to_u64(address), ps, off);
            if (!ok_or_record_error_locked(listed, "ListDataItems")) return false;
            const auto& rows = listed.value->data_items;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                if (to_i64(row.address) == address) {
                    dest.push_back(map_data_item(row));
                }
            }
            return true;
        });
    }

    bool read_decomp_lvars(std::vector<model::DecompLvarRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(128, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListDecompilations(kAllAddressesMin, kAllAddressesMax, ps, off, 30000);
            if (!ok_or_record_error_locked(listed, "ListDecompilations")) return false;
            const auto& rows = listed.value->decompilations;
            count = rows.size();
            for (const auto& row : rows) {
                auto detail = to_decompilation_detail(row);
                dest.insert(dest.end(), detail.locals.begin(), detail.locals.end());
            }
            return true;
        });
    }

    bool read_decomp_comments(std::vector<model::DecompCommentRow>& out) const override {
        out.clear();
        std::vector<model::CommentRow> comments;
        std::vector<model::FunctionRow> functions;
        if (!read_comments(comments) || !read_functions(functions)) {
            return false;
        }

        auto find_owner = [&](std::int64_t ea) -> std::int64_t {
            for (const auto& fn : functions) {
                const std::int64_t fn_end =
                    fn.end_ea > fn.address ? fn.end_ea : (fn.address + std::max<std::int64_t>(fn.size, 1));
                if (ea >= fn.address && ea < fn_end) {
                    return fn.address;
                }
            }
            return 0;
        };

        out.reserve(comments.size());
        for (const auto& comment : comments) {
            model::DecompCommentRow row;
            row.func_addr = find_owner(comment.address);
            row.address = comment.address;
            row.comment = comment.comment;
            row.source = comment.source;
            out.push_back(std::move(row));
        }
        return true;
    }

    bool read_decomp_tokens(std::vector<model::DecompTokenRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(128, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListDecompilations(kAllAddressesMin, kAllAddressesMax, ps, off, 30000);
            if (!ok_or_record_error_locked(listed, "ListDecompilations")) return false;
            const auto& rows = listed.value->decompilations;
            count = rows.size();
            for (const auto& row : rows) {
                const std::int64_t func_addr = to_i64(row.function_entry_address);
                std::int64_t token_idx = 0;
                for (const auto& t : row.tokens) {
                    model::DecompTokenRow mapped;
                    mapped.func_addr = func_addr;
                    mapped.token_index = token_idx++;
                    mapped.text = t.text;
                    mapped.kind = decomp_token_kind_name(t.kind);
                    mapped.line = t.line_number;
                    mapped.column = t.column_offset;
                    mapped.var_name = t.var_name;
                    mapped.var_type = t.var_type;
                    mapped.var_storage = t.var_storage;
                    dest.push_back(std::move(mapped));
                }
            }
            return true;
        });
    }

    bool read_parity_findings(std::vector<model::ParityFindingRow>& out) const override {
        out.clear();
        return true;
    }

    bool read_perf_benchmarks(std::vector<model::PerfBenchmarkRow>& out) const override {
        out.clear();
        return true;
    }

    bool read_signatures(std::vector<model::SignatureRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListFunctionSignatures(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListFunctionSignatures")) return false;
            const auto& rows = listed.value->signatures;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::SignatureRow mapped;
                mapped.sig_id = "func:" + to_hex(to_i64(row.function_entry_address));
                mapped.owner_kind = "function";
                mapped.owner_addr = to_i64(row.function_entry_address);
                mapped.name = row.function_name;
                mapped.prototype = row.prototype;
                mapped.calling_convention = row.calling_convention;
                mapped.is_variadic = row.has_var_args ? 1 : 0;
                mapped.return_type = row.return_type;
                mapped.param_count = static_cast<std::int64_t>(row.parameters.size());
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_function_params(std::vector<model::FunctionParamRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(1024, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListFunctionSignatures(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListFunctionSignatures")) return false;
            const auto& rows = listed.value->signatures;
            count = rows.size();
            for (const auto& sig : rows) {
                std::int64_t ordinal = 0;
                for (const auto& param : sig.parameters) {
                    model::FunctionParamRow mapped;
                    mapped.func_addr = to_i64(sig.function_entry_address);
                    mapped.ordinal = ordinal++;
                    mapped.param_name = param.name;
                    mapped.param_type = param.data_type.empty() ? param.formal_data_type : param.data_type;
                    mapped.storage.clear();
                    mapped.is_user_named = param.is_auto_parameter ? 0 : 1;
                    dest.push_back(std::move(mapped));
                }
            }
            return true;
        });
    }

    bool read_types(std::vector<model::TypeRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(4096, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListTypes("", ps, off);
            if (!ok_or_record_error_locked(listed, "ListTypes")) return false;
            const auto& rows = listed.value->types;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::TypeRow mapped;
                mapped.type_id = row.path_name.empty() ? std::to_string(row.type_id) : row.path_name;
                mapped.name = row.display_name.empty() ? row.name : row.display_name;
                mapped.kind = normalize_type_kind(row.kind);
                mapped.size = row.length;
                mapped.declaration = row.display_name.empty() ? row.name : row.display_name;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_type_aliases(std::vector<model::TypeAliasRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListTypeAliases("", ps, off);
            if (!ok_or_record_error_locked(listed, "ListTypeAliases")) return false;
            const auto& rows = listed.value->aliases;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::TypeAliasRow mapped;
                mapped.type_id = row.path_name.empty() ? std::to_string(row.type_id) : row.path_name;
                mapped.name = row.name;
                mapped.target_type = row.target_type;
                mapped.declaration = row.declaration;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_type_unions(std::vector<model::TypeUnionRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListTypeUnions("", ps, off);
            if (!ok_or_record_error_locked(listed, "ListTypeUnions")) return false;
            const auto& rows = listed.value->unions;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::TypeUnionRow mapped;
                mapped.type_id = row.path_name.empty() ? std::to_string(row.type_id) : row.path_name;
                mapped.name = row.name;
                mapped.size = to_i64(row.size);
                mapped.declaration = row.declaration;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_type_enums(std::vector<model::TypeEnumRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(2048, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListTypeEnums("", ps, off);
            if (!ok_or_record_error_locked(listed, "ListTypeEnums")) return false;
            const auto& rows = listed.value->enums;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::TypeEnumRow mapped;
                mapped.type_id = row.path_name.empty() ? std::to_string(row.type_id) : row.path_name;
                mapped.name = row.name;
                mapped.width = to_i64(row.width);
                mapped.is_signed = row.is_signed ? 1 : 0;
                mapped.declaration = row.declaration;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_type_enum_members(std::vector<model::TypeEnumMemberRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(4096, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListTypeEnumMembers("", ps, off);
            if (!ok_or_record_error_locked(listed, "ListTypeEnumMembers")) return false;
            const auto& rows = listed.value->members;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::TypeEnumMemberRow mapped;
                mapped.type_id = row.type_path_name.empty() ? std::to_string(row.type_id) : row.type_path_name;
                mapped.name = row.name;
                mapped.value = row.value;
                mapped.ordinal = to_i64(row.ordinal);
                mapped.comment = row.comment;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_type_members(std::vector<model::TypeMemberRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(4096, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListTypeMembers("", ps, off);
            if (!ok_or_record_error_locked(listed, "ListTypeMembers")) return false;
            const auto& rows = listed.value->members;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::TypeMemberRow mapped;
                mapped.parent_type_id = row.parent_type_path_name.empty()
                        ? std::to_string(row.parent_type_id)
                        : row.parent_type_path_name;
                mapped.parent_type_name = row.parent_type_name;
                mapped.member_name = row.name;
                mapped.member_type = row.member_type;
                mapped.offset = row.offset;
                mapped.size = to_i64(row.size);
                mapped.ordinal = to_i64(row.ordinal);
                mapped.comment = row.comment;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_pseudocode(std::vector<model::PseudocodeRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(256, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListDecompilations(kAllAddressesMin, kAllAddressesMax, ps, off, 30000);
            if (!ok_or_record_error_locked(listed, "ListDecompilations")) return false;
            const auto& rows = listed.value->decompilations;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                auto detail = to_decompilation_detail(row);
                model::PseudocodeRow mapped;
                mapped.func_addr = detail.func_addr;
                mapped.func_name = detail.func_name;
                mapped.text = detail.pseudocode;
                mapped.is_stale = (!detail.completed || detail.is_fallback) ? 1 : 0;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_instructions(std::vector<model::InstructionRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(4096, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListInstructions(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListInstructions")) return false;
            const auto& rows = listed.value->instructions;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                dest.push_back(map_instruction(row));
            }
            return true;
        });
    }

    bool read_instruction_at(std::int64_t address, model::InstructionRow& out) const override {
        out = {};
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        auto got = client_.GetInstruction(to_u64(address));
        if (!ok_or_record_error_locked(got, "GetInstruction")) return false;
        if (!got.value->instruction.has_value()) {
            last_error_.clear();
            return false;
        }
        out = map_instruction(*got.value->instruction);
        last_error_.clear();
        return true;
    }

    bool read_comments(std::vector<model::CommentRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(4096, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.GetComments(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "GetComments")) return false;
            const auto& rows = listed.value->comments;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                dest.push_back(map_comment(row));
            }
            return true;
        });
    }

    bool read_comments_at(std::int64_t address, std::vector<model::CommentRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        // Narrow range: only fetch comments at this exact address.
        auto listed = client_.GetComments(to_u64(address), to_u64(address), 256, 0);
        if (!ok_or_record_error_locked(listed, "GetComments")) {
            out.clear();
            return false;
        }
        for (const auto& row : listed.value->comments) {
            if (to_i64(row.address) == address) {
                out.push_back(map_comment(row));
            }
        }
        last_error_.clear();
        return true;
    }

    bool read_comments_in_range(
        std::int64_t start_address,
        std::int64_t end_address,
        std::vector<model::CommentRow>& out) const override {
        out.clear();
        if (end_address < start_address) {
            return true;
        }
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        return paginate_locked(4096, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.GetComments(to_u64(start_address), to_u64(end_address), ps, off);
            if (!ok_or_record_error_locked(listed, "GetComments")) return false;
            const auto& rows = listed.value->comments;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                const auto row_address = to_i64(row.address);
                if (row_address >= start_address && row_address <= end_address) {
                    dest.push_back(map_comment(row));
                }
            }
            return true;
        });
    }

    bool read_breakpoints(std::vector<model::BreakpointRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(4096, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListBreakpoints(kAllAddressesMin, kAllAddressesMax, ps, off, "", "");
            if (!ok_or_record_error_locked(listed, "ListBreakpoints")) return false;
            const auto& rows = listed.value->breakpoints;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                dest.push_back(map_breakpoint(row));
            }
            return true;
        });
    }

    bool read_breakpoints_at(std::int64_t address, std::vector<model::BreakpointRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(64, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListBreakpoints(to_u64(address), to_u64(address), ps, off, "", "");
            if (!ok_or_record_error_locked(listed, "ListBreakpoints")) return false;
            const auto& rows = listed.value->breakpoints;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                if (to_i64(row.address) == address) {
                    dest.push_back(map_breakpoint(row));
                }
            }
            return true;
        });
    }

    bool read_bookmarks(std::vector<model::BookmarkRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(4096, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListBookmarks(kAllAddressesMin, kAllAddressesMax, ps, off, "", "");
            if (!ok_or_record_error_locked(listed, "ListBookmarks")) return false;
            const auto& rows = listed.value->bookmarks;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                dest.push_back(map_bookmark(row));
            }
            return true;
        });
    }

    bool read_bookmarks_at(std::int64_t address, std::vector<model::BookmarkRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(64, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListBookmarks(to_u64(address), to_u64(address), ps, off, "", "");
            if (!ok_or_record_error_locked(listed, "ListBookmarks")) return false;
            const auto& rows = listed.value->bookmarks;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                if (to_i64(row.address) == address) {
                    dest.push_back(map_bookmark(row));
                }
            }
            return true;
        });
    }

    bool read_function_tags(std::vector<model::FunctionTagRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto listed = client_.ListFunctionTags();
        if (!ok_or_record_error_locked(listed, "ListFunctionTags")) {
            return false;
        }
        out.reserve(listed.value->tags.size());
        for (const auto& row : listed.value->tags) {
            model::FunctionTagRow mapped;
            mapped.name = row.name;
            mapped.comment = row.comment;
            out.push_back(std::move(mapped));
        }
        last_error_.clear();
        return true;
    }

    bool read_function_tag_mappings(std::vector<model::FunctionTagMappingRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto listed = client_.ListFunctionTagMappings(0);
        if (!ok_or_record_error_locked(listed, "ListFunctionTagMappings")) {
            return false;
        }
        out.reserve(listed.value->mappings.size());
        for (const auto& row : listed.value->mappings) {
            model::FunctionTagMappingRow mapped;
            mapped.func_addr = to_i64(row.function_entry);
            mapped.tag_name = row.tag_name;
            out.push_back(std::move(mapped));
        }
        last_error_.clear();
        return true;
    }

    bool read_symbols(std::vector<model::SymbolRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(4096, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListSymbols(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListSymbols")) return false;
            const auto& rows = listed.value->symbols;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                dest.push_back(map_symbol(row));
            }
            return true;
        });
    }

    bool read_symbols_at(std::int64_t address, std::vector<model::SymbolRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(64, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListSymbols(to_u64(address), to_u64(address), ps, off);
            if (!ok_or_record_error_locked(listed, "ListSymbols")) return false;
            const auto& rows = listed.value->symbols;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                if (to_i64(row.address) == address) {
                    dest.push_back(map_symbol(row));
                }
            }
            return true;
        });
    }

    bool read_xrefs(std::vector<model::XrefRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) return false;
        return paginate_locked(4096, out, [&](int ps, int off, auto& dest, std::size_t& count) {
            auto listed = client_.ListXrefs(kAllAddressesMin, kAllAddressesMax, ps, off);
            if (!ok_or_record_error_locked(listed, "ListXrefs")) return false;
            const auto& rows = listed.value->xrefs;
            count = rows.size();
            dest.reserve(dest.size() + count);
            for (const auto& row : rows) {
                model::XrefRow mapped;
                mapped.from_ea = to_i64(row.from_address);
                mapped.to_ea = to_i64(row.to_address);
                mapped.kind = row.ref_type;
                mapped.is_code = row.is_flow ? 1 : 0;
                mapped.is_data = row.is_memory ? 1 : 0;
                dest.push_back(std::move(mapped));
            }
            return true;
        });
    }

    bool read_program_info(model::ProgramInfoRow& out) const override {
        out = {};
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }

        auto status = client_.GetStatus();
        if (!ok_or_record_error_locked(status, "GetStatus")) {
            return false;
        }
        out.tool_name = status.value->service_name.empty() ? "libghidra" : status.value->service_name;
        out.analysis_id = std::string("libghidra:") + status.value->host_mode;
        out.is_headless = status.value->host_mode == "headless" ? 1 : 0;
        out.revision = to_i64(status.value->modification_number);

        auto rev = client_.GetRevision();
        if (rev.ok()) {
            out.revision = to_i64(rev.value->modification_number);
        }

        // The host knows the active program's path via the revision even when the client
        // never issued an explicit OpenProgram (e.g. headless --binary, where the host binds
        // the imported program as the active program). Use it so db_info reports the real
        // program instead of the "active-program" placeholder.
        std::string active_path = rev.ok() ? rev.value->program_path : std::string();
        if (active_path.empty()) {
            active_path = options_.program_path;
        }

        if (!opened_program_.has_value() && !active_path.empty()) {
            // Best-effort open to populate language/compiler/image-base metadata. Non-fatal:
            // analysis queries already run against the active program regardless of this.
            libghidra::client::OpenProgramRequest req;
            req.project_path = options_.project_path;
            req.project_name = options_.project_name;
            req.program_path = active_path;
            req.read_only = options_.read_only;
            auto opened = client_.OpenProgram(req);
            if (opened.ok()) {
                opened_program_ = *opened.value;
                opened_project_ = true;
            }
        }

        if (opened_program_.has_value()) {
            out.program_name = opened_program_->program_name;
            out.language_id = opened_program_->language_id;
            out.compiler_spec = opened_program_->compiler_spec;
            out.image_base = to_i64(opened_program_->image_base);
            out.md5 = opened_program_->md5;
            out.sha256 = opened_program_->sha256;
        } else {
            out.program_name = active_path.empty() ? "active-program" : active_path;
        }
        out.program_path = active_path.empty() ? out.program_name : active_path;
        last_error_.clear();
        return true;
    }

    bool read_freshness_token(SourceFreshnessToken& out) const override {
        out = {};
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto rev = client_.GetRevision();
        if (!ok_or_record_error_locked(rev, "GetRevision")) {
            return false;
        }
        out.program_id = std::to_string(rev.value->program_id);
        out.modification_number = to_i64(rev.value->modification_number);
        out.program_path = rev.value->program_path;
        out.file_id = rev.value->file_id;
        out.file_version = rev.value->file_version;
        out.file_last_modified_time = rev.value->file_last_modified_time;
        if (out.program_path.empty()) {
            out.program_path = options_.program_path;
        }
        last_error_.clear();
        return true;
    }

    bool read_program_revision(std::int64_t& out) const override {
        out = 0;
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto rev = client_.GetRevision();
        if (!ok_or_record_error_locked(rev, "GetRevision")) {
            return false;
        }
        out = to_i64(rev.value->modification_number);
        last_error_.clear();
        return true;
    }

    bool read_capabilities(std::vector<model::CapabilityRow>& out) const override {
        out.clear();
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }

        auto caps = client_.GetCapabilities();
        if (!ok_or_record_error_locked(caps, "GetCapabilities")) {
            out.clear();
            return false;
        }

        out.reserve(caps.value->size());
        for (const auto& cap : *caps.value) {
            model::CapabilityRow mapped;
            mapped.area = "libghidra";
            mapped.feature = cap.id;
            mapped.state = cap.status;
            mapped.notes = cap.note;
            mapped.since_rev.clear();
            out.push_back(std::move(mapped));
        }

        auto rev = client_.GetRevision();
        if (rev.ok()) {
            const auto since = std::to_string(rev.value->modification_number);
            for (auto& row : out) {
                row.since_rev = since;
            }
        }
        last_error_.clear();
        return true;
    }

    bool read_live_meta(std::vector<model::LiveMetaRow>& out) const override {
        out.clear();
        last_error_.clear();
        return false;
    }

    bool rename_function(std::int64_t address, const std::string& new_name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        trace_rpc_locked("RenameFunction");
        auto renamed = client_.RenameFunction(to_u64(address), new_name);
        if (!ok_or_record_error_locked(renamed, "RenameFunction") || !renamed.value->renamed) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool rename_symbol(std::int64_t address, const std::string& new_name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto renamed = client_.RenameSymbol(to_u64(address), new_name);
        if (!ok_or_record_error_locked(renamed, "RenameSymbol") || !renamed.value->renamed) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool delete_symbol(std::int64_t address, const std::string& name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteSymbol(to_u64(address), name);
        if (!ok_or_record_error_locked(deleted, "DeleteSymbol") || !deleted.value->deleted) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool rename_data_item(std::int64_t address, const std::string& new_name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto renamed = client_.RenameDataItem(to_u64(address), new_name);
        if (!ok_or_record_error_locked(renamed, "RenameDataItem") || !renamed.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool set_data_item_type(std::int64_t address, const std::string& new_type) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.ApplyDataType(to_u64(address), new_type);
        if (!ok_or_record_error_locked(updated, "ApplyDataType") || !updated.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool delete_data_item(std::int64_t address) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteDataItem(to_u64(address));
        if (!ok_or_record_error_locked(deleted, "DeleteDataItem") || !deleted.value->deleted) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool create_symbol(std::int64_t address, const std::string& name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto renamed = client_.RenameSymbol(to_u64(address), name);
        if (!ok_or_record_error_locked(renamed, "RenameSymbol") || !renamed.value->renamed) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool create_data_item(std::int64_t address, const std::string& data_type, const std::string& name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto applied = client_.ApplyDataType(to_u64(address), data_type);
        if (!ok_or_record_error_locked(applied, "ApplyDataType") || !applied.value->updated) {
            return false;
        }
        if (!name.empty()) {
            auto renamed = client_.RenameDataItem(to_u64(address), name);
            if (!ok_or_record_error_locked(renamed, "RenameDataItem") || !renamed.value->updated) {
                return false;
            }
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool write_byte(std::int64_t address, std::uint8_t value) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto written = client_.WriteBytes(to_u64(address), {value});
        if (!ok_or_record_error_locked(written, "WriteBytes") || written.value->bytes_written == 0) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool set_comment(std::int64_t address, const std::string& comment, bool repeatable) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto set = client_.SetComment(
            to_u64(address),
            repeatable ? libghidra::client::CommentKind::kRepeatable : libghidra::client::CommentKind::kEol,
            comment);
        if (!ok_or_record_error_locked(set, "SetComment") || !set.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool delete_comment(std::int64_t address, bool repeatable) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteComment(
            to_u64(address),
            repeatable ? libghidra::client::CommentKind::kRepeatable : libghidra::client::CommentKind::kEol);
        if (!ok_or_record_error_locked(deleted, "DeleteComment") || !deleted.value->deleted) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool set_comment_by_kind(std::int64_t address, const std::string& comment, const std::string& kind) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto set = client_.SetComment(to_u64(address), string_to_comment_kind(kind), comment);
        if (!ok_or_record_error_locked(set, "SetComment") || !set.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool delete_comment_by_kind(std::int64_t address, const std::string& kind) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteComment(to_u64(address), string_to_comment_kind(kind));
        if (!ok_or_record_error_locked(deleted, "DeleteComment") || !deleted.value->deleted) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool set_function_signature(std::int64_t owner_addr, const std::string& prototype) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        trace_rpc_locked("SetFunctionSignature");
        auto updated = client_.SetFunctionSignature(to_u64(owner_addr), prototype);
        if (!ok_or_record_error_locked(updated, "SetFunctionSignature")) {
            return false;
        }
        if (!updated.value->updated) {
            if (last_error_.empty()) {
                last_error_ = "SetFunctionSignature rejected prototype";
            }
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool rename_function_param(std::int64_t func_addr, std::int64_t ordinal, const std::string& new_name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.RenameFunctionParameter(to_u64(func_addr), static_cast<int>(ordinal), new_name);
        if (!ok_or_record_error_locked(updated, "RenameFunctionParameter")) {
            return false;
        }
        if (!updated.value->updated) {
            if (last_error_.empty()) {
                last_error_ = "RenameFunctionParameter rejected";
            }
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool set_function_param_type(
        std::int64_t func_addr,
        std::int64_t ordinal,
        const std::string& new_type) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetFunctionParameterType(to_u64(func_addr), static_cast<int>(ordinal), new_type);
        if (!ok_or_record_error_locked(updated, "SetFunctionParameterType")) {
            return false;
        }
        if (!updated.value->updated) {
            if (last_error_.empty()) {
                last_error_ = "SetFunctionParameterType rejected";
            }
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool rename_decomp_local(
        std::int64_t func_addr,
        const std::string& local_id,
        const std::string& new_name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.RenameFunctionLocal(to_u64(func_addr), local_id, new_name);
        if (!ok_or_record_error_locked(updated, "RenameFunctionLocal")) {
            return false;
        }
        if (!updated.value->updated) {
            if (last_error_.empty()) {
                last_error_ = "RenameFunctionLocal rejected";
            }
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool set_decomp_local_type(
        std::int64_t func_addr,
        const std::string& local_id,
        const std::string& new_type) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetFunctionLocalType(to_u64(func_addr), local_id, new_type);
        if (!ok_or_record_error_locked(updated, "SetFunctionLocalType")) {
            return false;
        }
        if (!updated.value->updated) {
            if (last_error_.empty()) {
                last_error_ = "SetFunctionLocalType rejected";
            }
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool add_breakpoint(
        std::int64_t address,
        int type,
        std::int64_t size,
        const std::string& condition,
        const std::string& group) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto added = client_.AddBreakpoint(
            to_u64(address),
            breakpoint_kind_from_type(type),
            to_u64(size),
            true,
            condition,
            group);
        if (!ok_or_record_error_locked(added, "AddBreakpoint") || !added.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool set_breakpoint_enabled(std::int64_t address, bool enabled) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetBreakpointEnabled(to_u64(address), enabled);
        if (!ok_or_record_error_locked(updated, "SetBreakpointEnabled") || !updated.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool set_breakpoint_type(std::int64_t address, int type) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetBreakpointKind(to_u64(address), breakpoint_kind_from_type(type));
        if (!ok_or_record_error_locked(updated, "SetBreakpointKind") || !updated.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool set_breakpoint_size(std::int64_t address, std::int64_t size) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetBreakpointSize(to_u64(address), to_u64(size));
        if (!ok_or_record_error_locked(updated, "SetBreakpointSize") || !updated.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool set_breakpoint_condition(std::int64_t address, const std::string& condition) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetBreakpointCondition(to_u64(address), condition);
        if (!ok_or_record_error_locked(updated, "SetBreakpointCondition") || !updated.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool set_breakpoint_group(std::int64_t address, const std::string& group) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetBreakpointGroup(to_u64(address), group);
        if (!ok_or_record_error_locked(updated, "SetBreakpointGroup") || !updated.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool delete_breakpoint(std::int64_t address) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteBreakpoint(to_u64(address));
        if (!ok_or_record_error_locked(deleted, "DeleteBreakpoint") || !deleted.value->deleted) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool add_bookmark(
        std::int64_t address,
        const std::string& type,
        const std::string& category,
        const std::string& comment) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto added = client_.AddBookmark(to_u64(address), type, category, comment);
        if (!ok_or_record_error_locked(added, "AddBookmark") || !added.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool set_bookmark_type(
        std::int64_t address,
        const std::string& old_type,
        const std::string& old_category,
        const std::string& new_type) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        libghidra::client::BookmarkRecord existing;
        if (!find_bookmark_locked(to_u64(address), old_type, old_category, existing)) {
            return false;
        }
        auto deleted = client_.DeleteBookmark(to_u64(address), old_type, old_category);
        if (!ok_or_record_error_locked(deleted, "DeleteBookmark") || !deleted.value->deleted) {
            return false;
        }
        auto added = client_.AddBookmark(to_u64(address), new_type, old_category, existing.comment);
        if (!ok_or_record_error_locked(added, "AddBookmark") || !added.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool set_bookmark_category(
        std::int64_t address,
        const std::string& type,
        const std::string& old_category,
        const std::string& new_category) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        libghidra::client::BookmarkRecord existing;
        if (!find_bookmark_locked(to_u64(address), type, old_category, existing)) {
            return false;
        }
        auto deleted = client_.DeleteBookmark(to_u64(address), type, old_category);
        if (!ok_or_record_error_locked(deleted, "DeleteBookmark") || !deleted.value->deleted) {
            return false;
        }
        auto added = client_.AddBookmark(to_u64(address), type, new_category, existing.comment);
        if (!ok_or_record_error_locked(added, "AddBookmark") || !added.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool set_bookmark_comment(
        std::int64_t address,
        const std::string& type,
        const std::string& category,
        const std::string& comment) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        libghidra::client::BookmarkRecord existing;
        if (!find_bookmark_locked(to_u64(address), type, category, existing)) {
            return false;
        }
        auto deleted = client_.DeleteBookmark(to_u64(address), type, category);
        if (!ok_or_record_error_locked(deleted, "DeleteBookmark") || !deleted.value->deleted) {
            return false;
        }
        auto added = client_.AddBookmark(to_u64(address), type, category, comment);
        if (!ok_or_record_error_locked(added, "AddBookmark") || !added.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool delete_bookmark(
        std::int64_t address,
        const std::string& type,
        const std::string& category) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteBookmark(to_u64(address), type, category);
        if (!ok_or_record_error_locked(deleted, "DeleteBookmark") || !deleted.value->deleted) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    // -- Function tags --------------------------------------------------------

    bool create_function_tag(
        const std::string& name,
        const std::string& comment) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto created = client_.CreateFunctionTag(name, comment);
        if (!ok_or_record_error_locked(created, "CreateFunctionTag") || !created.value->created) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool delete_function_tag(const std::string& name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteFunctionTag(name);
        if (!ok_or_record_error_locked(deleted, "DeleteFunctionTag") || !deleted.value->deleted) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool tag_function(
        std::int64_t func_addr,
        const std::string& tag_name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto tagged = client_.TagFunction(to_u64(func_addr), tag_name);
        if (!ok_or_record_error_locked(tagged, "TagFunction") || !tagged.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool untag_function(
        std::int64_t func_addr,
        const std::string& tag_name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto untagged = client_.UntagFunction(to_u64(func_addr), tag_name);
        if (!ok_or_record_error_locked(untagged, "UntagFunction") || !untagged.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool rename_type(const std::string& type_id, const std::string& new_name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.RenameType(type_id, new_name);
        if (!ok_or_record_error_locked(updated, "RenameType") || !updated.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool create_type(
        const std::string& name,
        const std::string& kind,
        std::int64_t size,
        const std::string& declaration) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        (void)declaration;
        const std::string normalized_kind = kind.empty() ? "struct" : kind;
        auto created = client_.CreateType(name, normalized_kind, to_u64(size));
        if (!ok_or_record_error_locked(created, "CreateType") || !created.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool delete_type(const std::string& type_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteType(type_id);
        if (!ok_or_record_error_locked(deleted, "DeleteType") || !deleted.value->deleted) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool create_type_alias(
        const std::string& name,
        const std::string& target_type) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto created = client_.CreateTypeAlias(name, target_type);
        if (!ok_or_record_error_locked(created, "CreateTypeAlias") || !created.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool delete_type_alias(const std::string& type_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteTypeAlias(type_id);
        if (!ok_or_record_error_locked(deleted, "DeleteTypeAlias") || !deleted.value->deleted) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool set_type_alias_target(
        const std::string& type_id,
        const std::string& target_type) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetTypeAliasTarget(type_id, target_type);
        if (!ok_or_record_error_locked(updated, "SetTypeAliasTarget") || !updated.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool create_type_enum(
        const std::string& name,
        std::int64_t width,
        bool is_signed) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto created = client_.CreateTypeEnum(name, to_u64(width), is_signed);
        if (!ok_or_record_error_locked(created, "CreateTypeEnum") || !created.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool delete_type_enum(const std::string& type_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteTypeEnum(type_id);
        if (!ok_or_record_error_locked(deleted, "DeleteTypeEnum") || !deleted.value->deleted) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool add_type_enum_member(
        const std::string& type_id,
        const std::string& name,
        std::int64_t value) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto created = client_.AddTypeEnumMember(type_id, name, value);
        if (!ok_or_record_error_locked(created, "AddTypeEnumMember") || !created.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool delete_type_enum_member(
        const std::string& type_id,
        std::int64_t ordinal) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteTypeEnumMember(type_id, to_u64(ordinal));
        if (!ok_or_record_error_locked(deleted, "DeleteTypeEnumMember") || !deleted.value->deleted) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool rename_type_member(
        const std::string& parent_type_id,
        std::int64_t ordinal,
        const std::string& new_name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.RenameTypeMember(parent_type_id, to_u64(ordinal), new_name);
        if (!ok_or_record_error_locked(updated, "RenameTypeMember") || !updated.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool add_type_member(
        const std::string& parent_type_id,
        const std::string& member_name,
        const std::string& member_type,
        std::int64_t size) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto created = client_.AddTypeMember(parent_type_id, member_name, member_type, to_u64(size));
        if (!ok_or_record_error_locked(created, "AddTypeMember") || !created.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool delete_type_member(
        const std::string& parent_type_id,
        std::int64_t ordinal) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteTypeMember(parent_type_id, to_u64(ordinal));
        if (!ok_or_record_error_locked(deleted, "DeleteTypeMember") || !deleted.value->deleted) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool set_type_member_type(
        const std::string& parent_type_id,
        std::int64_t ordinal,
        const std::string& new_type) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetTypeMemberType(parent_type_id, to_u64(ordinal), new_type);
        if (!ok_or_record_error_locked(updated, "SetTypeMemberType") || !updated.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool set_type_member_comment(
        const std::string& parent_type_id,
        std::int64_t ordinal,
        const std::string& comment) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetTypeMemberComment(parent_type_id, to_u64(ordinal), comment);
        if (!ok_or_record_error_locked(updated, "SetTypeMemberComment") || !updated.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool rename_type_enum_member(
        const std::string& type_id,
        std::int64_t ordinal,
        const std::string& new_name) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.RenameTypeEnumMember(type_id, to_u64(ordinal), new_name);
        if (!ok_or_record_error_locked(updated, "RenameTypeEnumMember") || !updated.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool set_type_enum_member_value(
        const std::string& type_id,
        std::int64_t ordinal,
        std::int64_t new_value) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetTypeEnumMemberValue(type_id, to_u64(ordinal), new_value);
        if (!ok_or_record_error_locked(updated, "SetTypeEnumMemberValue") || !updated.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool set_type_enum_member_comment(
        const std::string& type_id,
        std::int64_t ordinal,
        const std::string& comment) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto updated = client_.SetTypeEnumMemberComment(type_id, to_u64(ordinal), comment);
        if (!ok_or_record_error_locked(updated, "SetTypeEnumMemberComment") || !updated.value->updated) {
            return false;
        }
        maybe_auto_save_locked();
        return true;
    }

    bool create_type_union(
        const std::string& name,
        std::int64_t size,
        const std::string& declaration) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        (void)declaration;
        auto created = client_.CreateType(name, "union", to_u64(size));
        if (!ok_or_record_error_locked(created, "CreateType") || !created.value->updated) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool delete_type_union(const std::string& type_id) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto deleted = client_.DeleteType(type_id);
        if (!ok_or_record_error_locked(deleted, "DeleteType") || !deleted.value->deleted) {
            return false;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return true;
    }

    bool save_database() override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto saved = client_.SaveProgram();
        return ok_or_record_error_locked(saved, "SaveProgram") && saved.value->saved;
    }

    bool discard_changes() override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        auto discarded = client_.DiscardProgram();
        return ok_or_record_error_locked(discarded, "DiscardProgram") && discarded.value->discarded;
    }

    bool refresh() override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return false;
        }
        invalidate_decompile_cache_locked();
        auto rev = client_.GetRevision();
        return ok_or_record_error_locked(rev, "GetRevision");
    }

    int parse_declarations(const std::string& source_text) override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return -1;
        }
        auto parsed = client_.ParseDeclarations(source_text);
        if (!ok_or_record_error_locked(parsed, "ParseDeclarations")) {
            return -1;
        }
        if (!parsed.value->errors.empty()) {
            last_error_ = parsed.value->errors[0];
            return -1;
        }
        invalidate_decompile_cache_locked();
        maybe_auto_save_locked();
        return parsed.value->types_created;
    }

    std::string decompile(std::int64_t address) const override {
        auto detail = decompile_detail(address);
        return detail.has_value() ? detail->pseudocode : std::string{};
    }

    std::optional<model::DecompilationDetail> decompile_detail(std::int64_t address) const override {
        std::lock_guard<std::mutex> lock(mu_);
        if (!ensure_session_open_locked()) {
            return std::nullopt;
        }
        auto decomp = client_.GetDecompilation(to_u64(address), 30000);
        if (!ok_or_record_error_locked(decomp, "GetDecompilation")) {
            return std::nullopt;
        }
        if (!decomp.value->decompilation.has_value()) {
            last_error_ = "GetDecompilation returned empty response";
            return std::nullopt;
        }
        auto detail = to_decompilation_detail(*decomp.value->decompilation);
        if (detail.func_addr == 0) {
            detail.func_addr = address;
        }
        last_error_.clear();
        return detail;
    }

    bool has_authoritative_decompile_detail() const override {
        return true;
    }

private:
    void invalidate_decompile_cache_locked() const {
        // Query-scoped only: source does not retain decompilation state across queries.
    }

    static std::string to_decomp_local_role(libghidra::client::DecompileLocalKind kind) {
        switch (kind) {
            case libghidra::client::DecompileLocalKind::kParam:
                return "param";
            case libghidra::client::DecompileLocalKind::kTemp:
                return "temp";
            case libghidra::client::DecompileLocalKind::kLocal:
            case libghidra::client::DecompileLocalKind::kUnspecified:
            default:
                return "local";
        }
    }

    static std::string decomp_token_kind_name(libghidra::client::DecompileTokenKind kind) {
        switch (kind) {
            case libghidra::client::DecompileTokenKind::kKeyword: return "keyword";
            case libghidra::client::DecompileTokenKind::kComment: return "comment";
            case libghidra::client::DecompileTokenKind::kType: return "type";
            case libghidra::client::DecompileTokenKind::kFunction: return "function";
            case libghidra::client::DecompileTokenKind::kVariable: return "variable";
            case libghidra::client::DecompileTokenKind::kConst: return "const";
            case libghidra::client::DecompileTokenKind::kParameter: return "parameter";
            case libghidra::client::DecompileTokenKind::kGlobal: return "global";
            case libghidra::client::DecompileTokenKind::kDefault: return "default";
            case libghidra::client::DecompileTokenKind::kError: return "error";
            case libghidra::client::DecompileTokenKind::kSpecial: return "special";
            default: return "unknown";
        }
    }

    static model::DecompilationDetail to_decompilation_detail(
        const libghidra::client::DecompilationRecord& row)
    {
        model::DecompilationDetail detail;
        detail.func_addr = to_i64(row.function_entry_address);
        detail.func_name = row.function_name;
        detail.prototype = row.prototype;
        detail.pseudocode = row.pseudocode;
        detail.completed = row.completed;
        detail.is_fallback = row.is_fallback;
        detail.error_message = row.error_message;
        detail.locals.reserve(row.locals.size());
        for (const auto& local : row.locals) {
            model::DecompLvarRow mapped;
            mapped.func_addr = detail.func_addr;
            mapped.local_id = local.local_id;
            mapped.name = local.name.empty() ? local.local_id : local.name;
            mapped.type = local.data_type;
            mapped.storage = local.storage;
            mapped.role = to_decomp_local_role(local.kind);
            detail.locals.push_back(std::move(mapped));
        }
        detail.tokens.reserve(row.tokens.size());
        std::int64_t token_idx = 0;
        for (const auto& t : row.tokens) {
            model::DecompTokenRow mapped;
            mapped.func_addr = detail.func_addr;
            mapped.token_index = token_idx++;
            mapped.text = t.text;
            mapped.kind = decomp_token_kind_name(t.kind);
            mapped.line = t.line_number;
            mapped.column = t.column_offset;
            mapped.var_name = t.var_name;
            mapped.var_type = t.var_type;
            mapped.var_storage = t.var_storage;
            detail.tokens.push_back(std::move(mapped));
        }
        return detail;
    }

    void maybe_auto_save_locked() const {
        if (options_.auto_save_interval <= 0) {
            return;
        }
        ++mutation_count_;
        if (mutation_count_ % options_.auto_save_interval == 0) {
            auto saved = client_.SaveProgram();
            if (!saved.ok() || !saved.value->saved) {
                last_error_ = "auto-save failed after " + std::to_string(mutation_count_) + " mutations";
            }
        }
    }

    template <typename T>
    bool ok_or_record_error_locked(const libghidra::client::StatusOr<T>& status_or, const char* op) const {
        if (status_or.ok()) {
            return true;
        }
        std::ostringstream out;
        out << op << " failed";
        if (!status_or.status.code.empty()) {
            out << " [" << status_or.status.code << "]";
        }
        if (!status_or.status.message.empty()) {
            out << ": " << status_or.status.message;
        }
        last_error_ = out.str();
        xsql::set_vtab_error(last_error_);
        return false;
    }

    // Paginated read helper. `fetch_page` is called with (page_size, offset) and
    // must return true on success, writing items into `out` and setting `count`
    // to the number of items fetched.
    template <typename ModelRow, typename FetchPage>
    bool paginate_locked(int page_size, std::vector<ModelRow>& out, FetchPage&& fetch_page) const {
        int offset = 0;
        for (;;) {
            std::size_t count = 0;
            if (!fetch_page(page_size, offset, out, count)) {
                out.clear();
                return false;
            }
            if (count == 0) break;
            if (count < static_cast<std::size_t>(page_size)) break;
            offset += static_cast<int>(count);
        }
        last_error_.clear();
        return true;
    }

    bool should_open_program_locked() const {
        return options_.auto_open_program || !options_.project_path.empty() ||
               !options_.project_name.empty() || !options_.program_path.empty();
    }

    bool should_open_project_locked() const {
        return !options_.project_path.empty() || !options_.project_name.empty();
    }

    bool ensure_project_open_locked() const {
        if (opened_program_.has_value()) {
            return true;
        }
        if (should_open_program_locked() && !options_.program_path.empty()) {
            return ensure_session_open_locked();
        }
        if (opened_project_) {
            return true;
        }
        if (!should_open_project_locked()) {
            return true;
        }
        libghidra::client::OpenProjectRequest req;
        req.project_path = options_.project_path;
        req.project_name = options_.project_name;
        req.create = false;
        req.read_only = options_.read_only;
        auto opened = client_.OpenProject(req);
        if (!ok_or_record_error_locked(opened, "OpenProject")) {
            return false;
        }
        opened_project_ = true;
        last_error_.clear();
        return true;
    }

    bool ensure_session_open_locked() const {
        if (!should_open_program_locked()) {
            return true;
        }
        if (opened_program_.has_value()) {
            return true;
        }
        libghidra::client::OpenProgramRequest req;
        req.project_path = options_.project_path;
        req.project_name = options_.project_name;
        req.program_path = options_.program_path;
        req.analyze = options_.analyze;
        req.read_only = options_.read_only;
        auto opened = client_.OpenProgram(req);
        if (!ok_or_record_error_locked(opened, "OpenProgram")) {
            return false;
        }
        opened_program_ = *opened.value;
        opened_project_ = true;
        last_error_.clear();
        return true;
    }

    bool find_bookmark_locked(
        std::uint64_t address,
        const std::string& type,
        const std::string& category,
        libghidra::client::BookmarkRecord& out) const {
        constexpr int kPageSize = 256;
        int offset = 0;
        for (;;) {
            auto listed = client_.ListBookmarks(address, address, kPageSize, offset, type, category);
            if (!ok_or_record_error_locked(listed, "ListBookmarks")) {
                return false;
            }
            const auto& rows = listed.value->bookmarks;
            if (rows.empty()) {
                break;
            }
            for (const auto& row : rows) {
                if (row.address == address && row.type == type && row.category == category) {
                    out = row;
                    last_error_.clear();
                    return true;
                }
            }
            if (rows.size() < static_cast<std::size_t>(kPageSize)) {
                break;
            }
            offset += static_cast<int>(rows.size());
        }
        last_error_ =
            "bookmark not found at " + to_hex(to_i64(address)) + " (" + type + "/" + category + ")";
        return false;
    }

    static std::int64_t to_i64(std::uint64_t value) {
        if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
            return std::numeric_limits<std::int64_t>::max();
        }
        return static_cast<std::int64_t>(value);
    }

    static std::uint64_t to_u64(std::int64_t value) {
        return value < 0 ? 0ULL : static_cast<std::uint64_t>(value);
    }

    static std::string to_hex(std::int64_t value) {
        std::ostringstream out;
        out << "0x" << std::hex << std::uppercase << static_cast<unsigned long long>(to_u64(value));
        return out.str();
    }

    static model::FunctionRow map_function(const libghidra::client::FunctionRecord& row) {
        model::FunctionRow mapped;
        mapped.address = to_i64(row.entry_address);
        mapped.name = row.name;
        mapped.size = to_i64(row.size);
        mapped.end_ea = row.end_address != 0 ? to_i64(row.end_address) : (mapped.address + mapped.size);
        mapped.flags = row.is_thunk ? 1 : 0;
        mapped.namespace_name = row.namespace_name;
        mapped.signature = row.prototype;
        return mapped;
    }

    static model::SymbolRow map_symbol(const libghidra::client::SymbolRecord& row) {
        model::SymbolRow mapped;
        mapped.address = to_i64(row.address);
        mapped.name = row.name;
        mapped.symbol_kind = row.type;
        mapped.namespace_name = row.namespace_name;
        mapped.is_primary = row.is_primary ? 1 : 0;
        mapped.is_external = row.is_external ? 1 : 0;
        return mapped;
    }

    static model::StringRow map_string(const libghidra::client::DefinedStringRecord& row) {
        model::StringRow mapped;
        mapped.address = to_i64(row.address);
        mapped.content = row.value;
        mapped.length = static_cast<std::int64_t>(row.length);
        mapped.type = row.data_type;
        mapped.encoding = row.encoding;
        return mapped;
    }

    static model::DataItemRow map_data_item(const libghidra::client::DataItemRecord& row) {
        model::DataItemRow mapped;
        mapped.address = to_i64(row.address);
        mapped.name = row.name;
        mapped.data_type = row.data_type;
        mapped.size = to_i64(row.size);
        mapped.value_repr = row.value_repr;
        mapped.segment_name.clear();

        std::string lowered = mapped.data_type;
        std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        mapped.is_string =
            lowered.find("string") != std::string::npos || lowered.find("char") != std::string::npos ? 1 : 0;
        mapped.is_initialized = 0;
        return mapped;
    }

    static model::InstructionRow map_instruction(const libghidra::client::InstructionRecord& row) {
        model::InstructionRow mapped;
        mapped.address = to_i64(row.address);
        mapped.mnemonic = row.mnemonic;
        mapped.operands = row.operand_text;
        mapped.disasm = row.disassembly;
        mapped.size = static_cast<int>(row.length);
        mapped.bytes.clear();
        return mapped;
    }

    static std::string comment_kind_to_string(libghidra::client::CommentKind kind) {
        switch (kind) {
            case libghidra::client::CommentKind::kEol:
                return "eol";
            case libghidra::client::CommentKind::kPre:
                return "pre";
            case libghidra::client::CommentKind::kPost:
                return "post";
            case libghidra::client::CommentKind::kPlate:
                return "plate";
            case libghidra::client::CommentKind::kRepeatable:
                return "repeatable";
            case libghidra::client::CommentKind::kUnspecified:
            default:
                return "unspecified";
        }
    }

    static model::CommentRow map_comment(const libghidra::client::CommentRecord& row) {
        model::CommentRow mapped;
        mapped.address = to_i64(row.address);
        mapped.comment = row.text;
        mapped.repeatable = row.kind == libghidra::client::CommentKind::kRepeatable ? 1 : 0;
        mapped.source = comment_kind_to_string(row.kind);
        return mapped;
    }

    static libghidra::client::CommentKind string_to_comment_kind(const std::string& kind) {
        std::string normalized = kind;
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (normalized == "eol") return libghidra::client::CommentKind::kEol;
        if (normalized == "pre") return libghidra::client::CommentKind::kPre;
        if (normalized == "post") return libghidra::client::CommentKind::kPost;
        if (normalized == "plate") return libghidra::client::CommentKind::kPlate;
        if (normalized == "repeatable") return libghidra::client::CommentKind::kRepeatable;
        return libghidra::client::CommentKind::kEol;
    }

    static int breakpoint_type_from_kind(const std::string& kind) {
        std::string normalized = kind;
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (normalized == "hardware" || normalized == "read" || normalized == "write" || normalized == "access") {
            return 1;
        }
        return 0;
    }

    static model::BreakpointRow map_breakpoint(const libghidra::client::BreakpointRecord& row) {
        model::BreakpointRow mapped;
        mapped.address = to_i64(row.address);
        mapped.enabled = row.enabled ? 1 : 0;
        mapped.type = breakpoint_type_from_kind(row.kind);
        mapped.size = to_i64(row.size);
        mapped.flags = 0;
        mapped.pass_count = 0;
        mapped.condition = row.condition;
        mapped.group = row.group;
        mapped.loc_type = 0;
        return mapped;
    }

    static model::BookmarkRow map_bookmark(const libghidra::client::BookmarkRecord& row) {
        model::BookmarkRow mapped;
        mapped.address = to_i64(row.address);
        mapped.type = row.type;
        mapped.category = row.category;
        mapped.comment = row.comment;
        return mapped;
    }

    static std::string normalize_type_kind(const std::string& kind) {
        std::string normalized = kind;
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (normalized == "struct") {
            return "struct";
        }
        if (normalized == "union") {
            return "union";
        }
        if (normalized == "enum") {
            return "enum";
        }
        if (normalized == "typedef") {
            return "typedef";
        }
        if (normalized == "builtin") {
            return "primitive";
        }
        return normalized.empty() ? "other" : normalized;
    }

    static std::string breakpoint_kind_from_type(int type) {
        return type == 0 ? "SOFTWARE" : "HARDWARE";
    }

    static bool rpc_trace_enabled() {
        static const bool enabled = []() {
            const char* value = std::getenv("GHIDRASQL_RPC_TRACE");
            return value != nullptr && value[0] != '\0' && std::string(value) != "0";
        }();
        return enabled;
    }

    void trace_rpc_locked(const char* op) const {
        if (!rpc_trace_enabled()) {
            return;
        }
        std::cerr << "[ghidrasql] libghidra RPC " << op << '\n';
    }

    int derive_bitness_locked() const {
        if (!opened_program_.has_value()) {
            return 0;
        }
        const auto& lang = opened_program_->language_id;
        // Ghidra language_id format: "processor:endian:size:variant"
        // e.g. "x86:LE:64:default", "ARM:LE:32:v8"
        // Extract the size field (third colon-separated component).
        std::size_t first = lang.find(':');
        if (first == std::string::npos) {
            return 0;
        }
        std::size_t second = lang.find(':', first + 1);
        if (second == std::string::npos) {
            return 0;
        }
        std::size_t third = lang.find(':', second + 1);
        std::string bits_str = (third != std::string::npos)
                                   ? lang.substr(second + 1, third - second - 1)
                                   : lang.substr(second + 1);
        if (bits_str == "64") {
            return 64;
        }
        if (bits_str == "32") {
            return 32;
        }
        if (bits_str == "16") {
            return 16;
        }
        return 0;
    }

    LibGhidraSourceOptions options_;
    mutable std::mutex mu_;
    mutable std::string last_error_;
    mutable std::optional<libghidra::client::OpenProgramResponse> opened_program_;
    mutable bool opened_project_ = false;
    mutable libghidra::client::HttpClient client_;
    mutable int mutation_count_ = 0;
};
#endif

std::shared_ptr<Source> create_libghidra_live_source(const LibGhidraSourceOptions& options) {
#ifdef GHIDRASQL_HAS_LIBGHIDRA
    return std::make_shared<LibGhidraSource>(options);
#else
    (void)options;
    return {};
#endif
}

}  // namespace ghidrasql
