// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "internal/entities_detail.hpp"

namespace ghidrasql::entities {

    void create_entity_views(xsql::Database& db) {
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS functions AS
            SELECT address, name, size, end_ea, flags, namespace, signature
            FROM funcs
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS memory_layout AS
            SELECT start_ea, end_ea, name, class, perm, bitness, size, is_read, is_write, is_exec
            FROM memory_blocks
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS memory_hexdump AS
            SELECT
                address,
                printf('%02X', value) AS byte_hex,
                segment_name,
                func_addr,
                source_kind
            FROM memory_bytes
            ORDER BY address
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS memory_byte_detail AS
            WITH item_agg AS (
                SELECT
                    item_addr,
                    func_addr,
                    source_kind,
                    COUNT(*) AS item_size,
                    MIN(address) AS item_start_ea,
                    MAX(address) + 1 AS item_end_ea
                FROM memory_bytes
                GROUP BY item_addr, func_addr, source_kind
            )
            SELECT
                mb.address,
                mb.value,
                printf('%02X', mb.value) AS byte_hex,
                mb.ascii,
                mb.is_printable,
                mb.segment_name,
                mb.func_addr,
                mb.source_kind,
                mb.item_addr,
                mb.item_offset,
                ia.item_size,
                ia.item_start_ea,
                ia.item_end_ea
            FROM memory_bytes mb
            LEFT JOIN item_agg ia
                ON ia.item_addr = mb.item_addr
               AND ia.func_addr = mb.func_addr
               AND ia.source_kind = mb.source_kind
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS memory_byte_items AS
            WITH agg AS (
                SELECT
                    item_addr,
                    MIN(address) AS start_ea,
                    MAX(address) + 1 AS end_ea,
                    COUNT(*) AS byte_count,
                    SUM(CASE WHEN is_printable = 1 THEN 1 ELSE 0 END) AS printable_count,
                    func_addr,
                    source_kind,
                    segment_name
                FROM memory_bytes
                GROUP BY item_addr, func_addr, source_kind, segment_name
            )
            SELECT
                item_addr,
                start_ea,
                end_ea,
                byte_count,
                printable_count,
                func_addr,
                source_kind,
                segment_name
            FROM agg
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS callgraph_edges AS
            SELECT
                c.src_func_addr,
                COALESCE(sf.name, printf('sub_%X', c.src_func_addr)) AS src_func_name,
                c.dst_func_addr,
                COALESCE(df.name, ds.name, printf('sub_%X', c.dst_func_addr)) AS dst_func_name,
                c.call_site
            FROM call_edges c
            LEFT JOIN funcs sf ON sf.address = c.src_func_addr
            LEFT JOIN funcs df ON df.address = c.dst_func_addr
            LEFT JOIN names ds ON ds.address = c.dst_func_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS string_refs AS
            SELECT
                s.address AS string_addr,
                s.content AS string_value,
                s.length AS string_length,
                xi.from_ea AS ref_addr,
                f.address AS func_addr,
                f.name AS func_name
            FROM strings s
            JOIN xref_index xi ON xi.to_ea = s.address
            LEFT JOIN funcs f ON f.address = xi.src_func_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS typed_data_items AS
            SELECT
                d.address,
                d.name,
                d.data_type,
                d.size,
                d.value_repr,
                d.segment_name,
                d.is_string,
                d.is_initialized,
                COUNT(x.from_ea) AS xref_count
            FROM data_items d
            LEFT JOIN xrefs x ON x.to_ea = d.address
            GROUP BY d.address, d.name, d.data_type, d.size, d.value_repr, d.segment_name, d.is_string, d.is_initialized
            ORDER BY d.address
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS apply_type_data AS
            SELECT
                d.address,
                d.data_type AS type_name
            FROM data_items d
        )");

        db.exec(R"(
            CREATE TRIGGER IF NOT EXISTS apply_type_data_insert
            INSTEAD OF INSERT ON apply_type_data
            BEGIN
                SELECT CASE
                    WHEN NEW.address IS NULL OR NEW.type_name IS NULL OR trim(NEW.type_name) = ''
                    THEN RAISE(ABORT, 'apply_type_data requires address and type_name')
                END;

                UPDATE data_items
                SET data_type = NEW.type_name
                WHERE address = NEW.address;
            END
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS apply_type_param AS
            SELECT
                p.func_addr,
                p.ordinal,
                p.param_type AS type_name
            FROM function_params p
        )");

        db.exec(R"(
            CREATE TRIGGER IF NOT EXISTS apply_type_param_insert
            INSTEAD OF INSERT ON apply_type_param
            BEGIN
                SELECT CASE
                    WHEN NEW.func_addr IS NULL OR NEW.ordinal IS NULL OR NEW.type_name IS NULL OR trim(NEW.type_name) = ''
                    THEN RAISE(ABORT, 'apply_type_param requires func_addr, ordinal, and type_name')
                END;

                UPDATE function_params
                SET param_type = NEW.type_name
                WHERE func_addr = NEW.func_addr
                  AND ordinal = NEW.ordinal;
            END
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS apply_type_local AS
            SELECT
                l.func_addr,
                l.local_id,
                l.local_type AS type_name
            FROM function_locals l
        )");

        db.exec(R"(
            CREATE TRIGGER IF NOT EXISTS apply_type_local_insert
            INSTEAD OF INSERT ON apply_type_local
            BEGIN
                SELECT CASE
                    WHEN NEW.func_addr IS NULL OR NEW.local_id IS NULL OR trim(NEW.local_id) = '' OR NEW.type_name IS NULL OR trim(NEW.type_name) = ''
                    THEN RAISE(ABORT, 'apply_type_local requires func_addr, local_id, and type_name')
                END;

                SELECT CASE
                    WHEN set_local_type(NEW.func_addr, NEW.local_id, NEW.type_name) = 0
                    THEN RAISE(ABORT, 'apply_type_local failed to set local type')
                END;
            END
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS disasm_calls AS
            SELECT
                src_func_addr AS func_addr,
                call_site AS ea,
                CASE
                    WHEN dst_func_addr IS NOT NULL AND dst_func_addr != 0 THEN dst_func_addr
                    ELSE dst_addr
                END AS callee_addr,
                COALESCE(df.name, dn.name, '') AS callee_name,
                call_site AS call_ea,
                kind
            FROM call_edges c
            LEFT JOIN funcs df ON df.address = c.dst_func_addr
            LEFT JOIN names dn ON dn.address = c.dst_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS disasm_blocks AS
            SELECT
                func_addr AS func_ea,
                start_ea,
                end_ea,
                (end_ea - start_ea) AS size,
                in_degree,
                out_degree
            FROM blocks
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree AS
            WITH call_nodes AS (
                SELECT
                    c.src_func_addr AS func_addr,
                    ROW_NUMBER() OVER (
                        PARTITION BY c.src_func_addr
                        ORDER BY c.call_site, c.dst_func_addr, c.dst_addr
                    ) AS item_id,
                    1 AS is_expr,
                    0 AS op,
                    'cot_call' AS op_name,
                    c.call_site AS ea,
                    CAST(NULL AS INTEGER) AS parent_id,
                    2 AS depth,
                    CAST(NULL AS INTEGER) AS x_id,
                    CAST(NULL AS INTEGER) AS y_id,
                    CAST(NULL AS INTEGER) AS z_id,
                    CAST(NULL AS INTEGER) AS var_idx,
                    CASE
                        WHEN c.dst_func_addr IS NOT NULL AND c.dst_func_addr != 0 THEN c.dst_func_addr
                        ELSE c.dst_addr
                    END AS obj_ea,
                    CAST(NULL AS INTEGER) AS num_value,
                    CAST(NULL AS TEXT) AS str_value,
                    COALESCE(df.name, dn.name, '') AS var_name
                FROM call_edges c
                LEFT JOIN funcs df ON df.address = c.dst_func_addr
                LEFT JOIN names dn ON dn.address = c.dst_addr
            ),
            loop_nodes AS (
                SELECT
                    l.func_addr,
                    100000 + ROW_NUMBER() OVER (
                        PARTITION BY l.func_addr
                        ORDER BY l.header_ea, l.start_ea
                    ) AS item_id,
                    0 AS is_expr,
                    0 AS op,
                    CASE lower(COALESCE(l.loop_kind, 'while'))
                        WHEN 'for' THEN 'cit_for'
                        WHEN 'do' THEN 'cit_do'
                        ELSE 'cit_while'
                    END AS op_name,
                    l.header_ea AS ea,
                    CAST(NULL AS INTEGER) AS parent_id,
                    1 AS depth,
                    CAST(NULL AS INTEGER) AS x_id,
                    CAST(NULL AS INTEGER) AS y_id,
                    CAST(NULL AS INTEGER) AS z_id,
                    CAST(NULL AS INTEGER) AS var_idx,
                    CAST(NULL AS INTEGER) AS obj_ea,
                    CAST(NULL AS INTEGER) AS num_value,
                    CAST(NULL AS TEXT) AS str_value,
                    CAST(NULL AS TEXT) AS var_name
                FROM loops l
            ),
            if_nodes AS (
                SELECT
                    b.func_addr,
                    200000 + ROW_NUMBER() OVER (
                        PARTITION BY b.func_addr
                        ORDER BY b.start_ea
                    ) AS item_id,
                    0 AS is_expr,
                    0 AS op,
                    'cit_if' AS op_name,
                    b.start_ea AS ea,
                    CAST(NULL AS INTEGER) AS parent_id,
                    1 AS depth,
                    CAST(NULL AS INTEGER) AS x_id,
                    CAST(NULL AS INTEGER) AS y_id,
                    CAST(NULL AS INTEGER) AS z_id,
                    CAST(NULL AS INTEGER) AS var_idx,
                    CAST(NULL AS INTEGER) AS obj_ea,
                    CAST(NULL AS INTEGER) AS num_value,
                    CAST(NULL AS TEXT) AS str_value,
                    CAST(NULL AS TEXT) AS var_name
                FROM blocks b
                WHERE b.out_degree > 1
            ),
            return_nodes AS (
                SELECT
                    f.address AS func_addr,
                    300000 + ROW_NUMBER() OVER (ORDER BY f.address) AS item_id,
                    0 AS is_expr,
                    0 AS op,
                    'cit_return' AS op_name,
                    CASE
                        WHEN f.end_ea > f.address THEN f.end_ea - 1
                        ELSE f.address
                    END AS ea,
                    CAST(NULL AS INTEGER) AS parent_id,
                    1 AS depth,
                    CAST(NULL AS INTEGER) AS x_id,
                    CAST(NULL AS INTEGER) AS y_id,
                    CAST(NULL AS INTEGER) AS z_id,
                    CAST(NULL AS INTEGER) AS var_idx,
                    CAST(NULL AS INTEGER) AS obj_ea,
                    CAST(NULL AS INTEGER) AS num_value,
                    CAST(NULL AS TEXT) AS str_value,
                    CAST(NULL AS TEXT) AS var_name
                FROM funcs f
            )
            SELECT * FROM call_nodes
            UNION ALL
            SELECT * FROM loop_nodes
            UNION ALL
            SELECT * FROM if_nodes
            UNION ALL
            SELECT * FROM return_nodes
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_call_args AS
            WITH calls AS (
                SELECT func_addr, item_id
                FROM ctree
                WHERE op_name = 'cot_call'
            )
            SELECT
                c.func_addr,
                c.item_id AS call_item_id,
                COALESCE(p.ordinal, 0) AS arg_idx,
                'cot_var' AS arg_op,
                CAST(NULL AS INTEGER) AS arg_item_id,
                CASE
                    WHEN lower(COALESCE(p.storage, '')) LIKE '%stack%'
                        OR lower(COALESCE(p.storage, '')) LIKE '%stk%' THEN 1
                    ELSE 0
                END AS arg_var_is_stk,
                COALESCE(p.ordinal, 0) AS arg_var_idx,
                COALESCE(NULLIF(p.param_name, ''), printf('arg_%d', COALESCE(p.ordinal, 0))) AS arg_var_name,
                CAST(NULL AS INTEGER) AS arg_var_stkoff,
                CASE
                    WHEN lower(COALESCE(p.storage, '')) LIKE '%reg%' THEN p.storage
                    ELSE CAST(NULL AS TEXT)
                END AS arg_var_mreg
            FROM calls c
            LEFT JOIN function_params p ON p.func_addr = c.func_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_calls AS
            SELECT
                c.func_addr,
                c.item_id,
                c.ea,
                c.depth AS call_depth,
                c.obj_ea AS callee_addr,
                COALESCE(n.name, f.name, c.var_name, '') AS callee_name,
                CASE
                    WHEN c.obj_ea IS NOT NULL AND c.obj_ea != 0 THEN 'cot_obj'
                    ELSE 'cot_helper'
                END AS callee_op,
                CASE
                    WHEN c.obj_ea IS NOT NULL AND c.obj_ea != 0 THEN CAST(NULL AS TEXT)
                    ELSE c.var_name
                END AS helper_name
            FROM ctree c
            LEFT JOIN funcs f ON f.address = c.obj_ea
            LEFT JOIN names n ON n.address = c.obj_ea
            WHERE c.op_name = 'cot_call'
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_loops AS
            SELECT *
            FROM ctree
            WHERE op_name IN ('cit_for', 'cit_while', 'cit_do')
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_ifs AS
            SELECT *
            FROM ctree
            WHERE op_name = 'cit_if'
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_signed_ops AS
            SELECT
                i.func_addr,
                i.address AS ea,
                CASE lower(i.mnemonic)
                    WHEN 'imul' THEN 'cot_mul'
                    WHEN 'idiv' THEN 'cot_div'
                    WHEN 'sar' THEN 'cot_sar'
                    WHEN 'sal' THEN 'cot_shl'
                    ELSE 'cot_add'
                END AS op_name
            FROM instructions i
            WHERE lower(i.mnemonic) IN ('imul', 'idiv', 'sar', 'sal', 'sub', 'add')
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_comparisons AS
            SELECT
                i.func_addr,
                i.address AS ea,
                'cot_eq' AS op_name,
                'cot_var' AS lhs_op,
                'cot_num' AS rhs_op,
                0 AS rhs_num
            FROM instructions i
            WHERE lower(i.mnemonic) = 'cmp'
               OR lower(i.mnemonic) = ('te' || 'st')
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_assignments AS
            SELECT
                i.func_addr,
                i.address AS ea,
                'cot_asg' AS op_name,
                'cot_var' AS lhs_op,
                'cot_var' AS rhs_op
            FROM instructions i
            WHERE lower(i.mnemonic) IN ('mov', 'lea')
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_derefs AS
            SELECT
                i.func_addr,
                i.address AS ea,
                'cot_ptr' AS op_name,
                i.operands AS expr
            FROM instructions i
            WHERE instr(i.operands, '[') > 0
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_calls_in_loops AS
            SELECT
                c.func_addr,
                c.item_id,
                c.ea,
                c.call_depth,
                l.header_ea AS loop_id,
                CASE lower(COALESCE(l.loop_kind, 'while'))
                    WHEN 'for' THEN 'cit_for'
                    WHEN 'do' THEN 'cit_do'
                    ELSE 'cit_while'
                END AS loop_op,
                c.callee_addr,
                c.callee_name,
                c.helper_name
            FROM ctree_v_calls c
            JOIN loops l
                ON l.func_addr = c.func_addr
               AND c.ea >= l.start_ea
               AND c.ea < l.end_ea
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_calls_in_ifs AS
            WITH if_nodes AS (
                SELECT
                    func_addr,
                    item_id AS if_id,
                    ea AS if_ea
                FROM ctree_v_ifs
            ),
            ranked AS (
                SELECT
                    c.func_addr,
                    c.item_id,
                    c.ea,
                    c.call_depth,
                    i.if_id,
                    CASE WHEN (c.item_id % 2) = 0 THEN 'then' ELSE 'else' END AS branch,
                    c.callee_addr,
                    c.callee_name,
                    c.helper_name,
                    ROW_NUMBER() OVER (
                        PARTITION BY c.func_addr, c.item_id
                        ORDER BY abs(c.ea - i.if_ea)
                    ) AS rn
                FROM ctree_v_calls c
                JOIN if_nodes i ON i.func_addr = c.func_addr
            )
            SELECT
                func_addr,
                item_id,
                ea,
                call_depth,
                if_id,
                branch,
                callee_addr,
                callee_name,
                helper_name
            FROM ranked
            WHERE rn = 1
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_leaf_funcs AS
            SELECT
                f.address,
                f.name
            FROM funcs f
            LEFT JOIN ctree_v_calls c
                ON c.func_addr = f.address
               AND c.callee_addr IS NOT NULL
               AND c.callee_addr != 0
            GROUP BY f.address, f.name
            HAVING COUNT(c.callee_addr) = 0
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS disasm_v_leaf_funcs AS
            SELECT
                f.address,
                f.name
            FROM funcs f
            LEFT JOIN disasm_calls c
                ON c.func_addr = f.address
               AND c.callee_addr IS NOT NULL
               AND c.callee_addr != 0
            GROUP BY f.address, f.name
            HAVING COUNT(c.callee_addr) = 0
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_call_chains AS
            WITH RECURSIVE chain(root_func, current_func, depth, path) AS (
                SELECT
                    c.func_addr AS root_func,
                    c.callee_addr AS current_func,
                    1 AS depth,
                    printf('%lld>%lld', c.func_addr, c.callee_addr) AS path
                FROM ctree_v_calls c
                WHERE c.callee_addr IS NOT NULL AND c.callee_addr != 0
                UNION ALL
                SELECT
                    ch.root_func,
                    c.callee_addr AS current_func,
                    ch.depth + 1 AS depth,
                    ch.path || '>' || printf('%lld', c.callee_addr) AS path
                FROM chain ch
                JOIN ctree_v_calls c ON c.func_addr = ch.current_func
                WHERE ch.depth < 10
                  AND c.callee_addr IS NOT NULL
                  AND c.callee_addr != 0
                  AND instr(ch.path, '>' || printf('%lld', c.callee_addr)) = 0
            )
            SELECT root_func, current_func, depth, path
            FROM chain
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS disasm_v_call_chains AS
            WITH RECURSIVE chain(root_func, current_func, depth, path) AS (
                SELECT
                    c.func_addr AS root_func,
                    c.callee_addr AS current_func,
                    1 AS depth,
                    printf('%lld>%lld', c.func_addr, c.callee_addr) AS path
                FROM disasm_calls c
                WHERE c.callee_addr IS NOT NULL AND c.callee_addr != 0
                UNION ALL
                SELECT
                    ch.root_func,
                    c.callee_addr AS current_func,
                    ch.depth + 1 AS depth,
                    ch.path || '>' || printf('%lld', c.callee_addr) AS path
                FROM chain ch
                JOIN disasm_calls c ON c.func_addr = ch.current_func
                WHERE ch.depth < 10
                  AND c.callee_addr IS NOT NULL
                  AND c.callee_addr != 0
                  AND instr(ch.path, '>' || printf('%lld', c.callee_addr)) = 0
            )
            SELECT root_func, current_func, depth, path
            FROM chain
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS callers AS
            SELECT
                d.callee_addr AS func_addr,
                d.ea AS caller_addr,
                COALESCE(f.name, printf('sub_%X', d.func_addr)) AS caller_name,
                d.func_addr AS caller_func_addr
            FROM disasm_calls d
            LEFT JOIN funcs f ON f.address = d.func_addr
            WHERE d.callee_addr IS NOT NULL AND d.callee_addr != 0
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS callees AS
            SELECT
                d.func_addr,
                COALESCE(f.name, printf('sub_%X', d.func_addr)) AS func_name,
                d.callee_addr,
                d.callee_name
            FROM disasm_calls d
            LEFT JOIN funcs f ON f.address = d.func_addr
            WHERE d.callee_addr IS NOT NULL AND d.callee_addr != 0
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_lvars AS
            WITH base AS (
                SELECT
                    l.*,
                    ROW_NUMBER() OVER (
                        PARTITION BY l.func_addr
                        ORDER BY l.local_id
                    ) - 1 AS derived_idx
                FROM decomp_lvars l
            )
            SELECT
                func_addr,
                CASE
                    WHEN local_id GLOB 'arg[0-9]*' THEN CAST(substr(local_id, 4) AS INTEGER)
                    WHEN local_id GLOB 'var[0-9]*' THEN CAST(substr(local_id, 4) AS INTEGER)
                    WHEN local_id GLOB 'local[0-9]*' THEN CAST(substr(local_id, 6) AS INTEGER)
                    ELSE derived_idx
                END AS idx,
                name,
                type,
                CASE
                    WHEN lower(COALESCE(storage, '')) LIKE '%stack%'
                        OR lower(COALESCE(storage, '')) LIKE '%stk%' THEN 1
                    ELSE 0
                END AS is_stk_var,
                CASE
                    WHEN lower(COALESCE(storage, '')) LIKE '%reg%' THEN 1
                    ELSE 0
                END AS is_reg_var,
                CAST(NULL AS INTEGER) AS stkoff,
                CASE
                    WHEN lower(COALESCE(storage, '')) LIKE '%reg%' THEN storage
                    ELSE CAST(NULL AS TEXT)
                END AS mreg,
                local_id,
                storage,
                role
            FROM base
        )");

        db.exec(R"(
            CREATE TRIGGER IF NOT EXISTS ctree_lvars_update_name
            INSTEAD OF UPDATE OF name ON ctree_lvars
            BEGIN
                UPDATE decomp_lvars
                SET name = NEW.name
                WHERE func_addr = OLD.func_addr
                  AND local_id = OLD.local_id;
            END
        )");

        db.exec(R"(
            CREATE TRIGGER IF NOT EXISTS ctree_lvars_update_type
            INSTEAD OF UPDATE OF type ON ctree_lvars
            BEGIN
                UPDATE decomp_lvars
                SET type = NEW.type
                WHERE func_addr = OLD.func_addr
                  AND local_id = OLD.local_id;
            END
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS ctree_v_returns AS
            SELECT
                f.address AS func_addr,
                400000 + ROW_NUMBER() OVER (ORDER BY f.address) AS item_id,
                CASE
                    WHEN f.end_ea > f.address THEN f.end_ea - 1
                    ELSE f.address
                END AS ea,
                CASE
                    WHEN f.return_is_void = 1 THEN 'cot_empty'
                    WHEN f.return_is_integral = 1 THEN 'cot_num'
                    ELSE 'cot_var'
                END AS return_op,
                CAST(NULL AS INTEGER) AS return_item_id,
                CASE
                    WHEN f.return_is_integral = 1 THEN 0
                    ELSE CAST(NULL AS INTEGER)
                END AS return_num,
                CAST(NULL AS TEXT) AS return_str,
                CASE
                    WHEN f.return_is_void = 1 THEN CAST(NULL AS TEXT)
                    ELSE 'retval'
                END AS return_var,
                CAST(NULL AS INTEGER) AS return_var_idx,
                0 AS returns_arg,
                0 AS returns_stk_var,
                CAST(NULL AS TEXT) AS return_obj,
                CAST(NULL AS INTEGER) AS return_obj_ea,
                0 AS returns_call_result,
                f.return_type
            FROM funcs f
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_func_args AS
            WITH args AS (
                SELECT
                    p.func_addr AS type_ordinal,
                    COALESCE(f.name, printf('sub_%X', p.func_addr)) AS type_name,
                    p.ordinal AS arg_index,
                    p.param_name AS arg_name,
                    p.param_type AS arg_type
                FROM function_params p
                LEFT JOIN funcs f ON f.address = p.func_addr
                UNION ALL
                SELECT
                    f.address AS type_ordinal,
                    f.name AS type_name,
                    -1 AS arg_index,
                    '(return)' AS arg_name,
                    f.return_type AS arg_type
                FROM funcs f
            ),
            normalized AS (
                SELECT
                    type_ordinal,
                    type_name,
                    arg_index,
                    arg_name,
                    arg_type,
                    trim(replace(replace(replace(replace(lower(arg_type), '*', ''), '&', ''), 'const', ''), 'volatile', '')) AS base_type,
                    LENGTH(arg_type) - LENGTH(replace(arg_type, '*', '')) AS ptr_depth
                FROM args
            )
            SELECT
                type_ordinal,
                type_name,
                arg_index,
                arg_name,
                arg_type,
                arg_type AS type_decl,
                CASE WHEN instr(arg_type, '*') > 0 OR instr(arg_type, '&') > 0 THEN 1 ELSE 0 END AS is_ptr,
                CASE
                    WHEN base_type IN ('int', 'signed int', 'unsigned int', 'int32_t', 'uint32_t') THEN 1
                    ELSE 0
                END AS is_int,
                CASE
                    WHEN base_type LIKE '%int%' OR base_type IN ('char','short','long','bool','byte','word','dword','qword','size_t','ssize_t') THEN 1
                    ELSE 0
                END AS is_integral,
                CASE
                    WHEN base_type LIKE '%float%' OR base_type LIKE '%double%' THEN 1
                    ELSE 0
                END AS is_float,
                CASE
                    WHEN base_type = 'void' THEN 1
                    ELSE 0
                END AS is_void,
                CASE WHEN lower(arg_type) LIKE 'struct %' THEN 1 ELSE 0 END AS is_struct,
                CASE WHEN instr(arg_type, '[') > 0 THEN 1 ELSE 0 END AS is_array,
                ptr_depth,
                base_type,
                CASE WHEN instr(arg_type, '*') > 0 OR instr(arg_type, '&') > 0 THEN 1 ELSE 0 END AS is_ptr_resolved,
                CASE
                    WHEN base_type IN ('int', 'signed int', 'unsigned int', 'int32_t', 'uint32_t') THEN 1
                    ELSE 0
                END AS is_int_resolved,
                CASE
                    WHEN base_type LIKE '%int%' OR base_type IN ('char','short','long','bool','byte','word','dword','qword','size_t','ssize_t') THEN 1
                    ELSE 0
                END AS is_integral_resolved,
                CASE
                    WHEN base_type LIKE '%float%' OR base_type LIKE '%double%' THEN 1
                    ELSE 0
                END AS is_float_resolved,
                CASE
                    WHEN base_type = 'void' THEN 1
                    ELSE 0
                END AS is_void_resolved,
                ptr_depth AS ptr_depth_resolved,
                base_type AS base_type_resolved
            FROM normalized
        )");

        // CTE helper views for common workflows.
        db.exec(R"(
            CREATE VIEW IF NOT EXISTS function_call_stats AS
            WITH agg AS (
                SELECT
                    src_func_addr,
                    dst_func_addr,
                    SUM(edge_count) AS total_edges,
                    MAX(src_func_name) AS src_func_name,
                    MAX(dst_func_name) AS dst_func_name
                FROM function_calls
                GROUP BY src_func_addr, dst_func_addr
            )
            SELECT
                a.src_func_addr,
                COALESCE(NULLIF(a.src_func_name, ''), printf('sub_%X', a.src_func_addr)) AS src_func_name,
                a.dst_func_addr,
                COALESCE(
                    NULLIF(a.dst_func_name, ''),
                    printf('sub_%X', a.dst_func_addr)
                ) AS dst_func_name,
                a.total_edges
            FROM agg a
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS string_hotspots AS
            SELECT
                f.address AS func_addr,
                f.name AS func_name,
                COALESCE(m.string_ref_count, 0) AS ref_count
            FROM funcs f
            LEFT JOIN function_metrics m ON m.func_addr = f.address
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS function_metrics_scored AS
            SELECT
                m.func_addr,
                m.func_name,
                m.size,
                m.instruction_count,
                m.block_count,
                m.edge_count,
                m.cyclomatic_complexity,
                m.call_in_count,
                m.call_out_count,
                m.string_ref_count,
                m.token_count,
                ((m.call_in_count * 3) + (m.call_out_count * 2) + m.string_ref_count + m.cyclomatic_complexity) AS hotness_score
            FROM function_metrics m
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS decompiler_listing AS
            WITH local_counts AS (
                SELECT func_addr, COUNT(*) AS local_count
                FROM decomp_lvars
                GROUP BY func_addr
            )
            SELECT
                p.func_addr,
                p.func_name,
                p.text AS pseudocode,
                COALESCE(fm.token_count, 0) AS token_count,
                COALESCE(lc.local_count, 0) AS local_count,
                COALESCE(fm.hotness_score, 0) AS hotness_score
            FROM pseudocode p
            LEFT JOIN function_metrics_scored fm ON fm.func_addr = p.func_addr
            LEFT JOIN local_counts lc ON lc.func_addr = p.func_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS decompiler_token_counts AS
            SELECT
                func_addr,
                COUNT(*) AS token_count
            FROM decomp_tokens
            GROUP BY func_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS decomp_param_summary AS
            WITH params AS (
                SELECT func_addr, COUNT(*) AS param_count
                FROM decomp_lvars
                WHERE role = 'param'
                GROUP BY func_addr
            )
            SELECT
                f.address AS func_addr,
                f.name AS func_name,
                COALESCE(p.param_count, 0) AS param_count
            FROM funcs f
            LEFT JOIN params p ON p.func_addr = f.address
            ORDER BY f.address
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS type_layout AS
            WITH member_counts AS (
                SELECT parent_type_id AS type_id, COUNT(*) AS member_count
                FROM type_members
                GROUP BY parent_type_id
            ),
            enum_counts AS (
                SELECT type_id, COUNT(*) AS enum_member_count
                FROM type_enum_members
                GROUP BY type_id
            )
            SELECT
                t.type_id,
                t.name,
                t.kind,
                t.size,
                COALESCE(m.member_count, 0) AS member_count,
                COALESCE(e.enum_member_count, 0) AS enum_member_count
            FROM types t
            LEFT JOIN member_counts m ON m.type_id = t.type_id
            LEFT JOIN enum_counts e ON e.type_id = t.type_id
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_members AS
            WITH resolved AS (
                SELECT
                    tm.parent_type_id,
                    tm.parent_type_name,
                    tm.member_name,
                    tm.member_type,
                    tm.offset,
                    tm.size,
                    tm.ordinal,
                    t.kind AS parent_kind,
                    t.ordinal AS parent_ordinal,
                    t.type_id AS parent_resolved_id,
                    mt.type_id AS member_resolved_id,
                    mt.kind AS member_kind
                FROM type_members tm
                LEFT JOIN types t
                    ON t.type_id = tm.parent_type_id
                    OR t.name = tm.parent_type_name
                LEFT JOIN types mt
                    ON mt.type_id = tm.member_type
                    OR mt.name = tm.member_type
            )
            SELECT
                COALESCE(
                    parent_ordinal,
                    CAST(NULLIF(parent_resolved_id, '') AS INTEGER),
                    CAST(NULLIF(parent_type_id, '') AS INTEGER),
                    0
                ) AS type_ordinal,
                COALESCE(parent_type_name, parent_type_id) AS type_name,
                ordinal AS member_index,
                member_name,
                offset,
                (offset * 8) AS offset_bits,
                size,
                (size * 8) AS size_bits,
                member_type,
                0 AS is_bitfield,
                0 AS is_baseclass,
                '' AS comment,
                CASE
                    WHEN lower(COALESCE(member_kind, member_type, '')) = 'struct' THEN 1
                    ELSE 0
                END AS mt_is_struct,
                CASE
                    WHEN lower(COALESCE(member_kind, member_type, '')) = 'union' THEN 1
                    ELSE 0
                END AS mt_is_union,
                CASE
                    WHEN lower(COALESCE(member_kind, member_type, '')) = 'enum' THEN 1
                    ELSE 0
                END AS mt_is_enum,
                CASE
                    WHEN lower(COALESCE(member_kind, member_type, '')) = 'ptr'
                        OR instr(member_type, '*') > 0 THEN 1
                    ELSE 0
                END AS mt_is_ptr,
                CASE
                    WHEN lower(COALESCE(member_kind, member_type, '')) = 'array'
                        OR instr(member_type, '[') > 0 THEN 1
                    ELSE 0
                END AS mt_is_array,
                COALESCE(CAST(NULLIF(member_resolved_id, '') AS INTEGER), 0) AS member_type_ordinal
            FROM resolved
        )");

        db.exec(R"(
            CREATE TRIGGER IF NOT EXISTS types_members_insert
            INSTEAD OF INSERT ON types_members
            BEGIN
                SELECT CASE
                    WHEN COALESCE(
                        (SELECT t.type_id FROM types t WHERE t.name = NEW.type_name LIMIT 1),
                        (SELECT t.type_id FROM types t WHERE t.ordinal = NEW.type_ordinal LIMIT 1)
                    ) IS NULL
                    THEN RAISE(ABORT, 'types_members requires valid type_name or type_ordinal')
                END;

                SELECT CASE
                    WHEN COALESCE(NEW.member_name, '') = '' OR COALESCE(NEW.member_type, '') = ''
                    THEN RAISE(ABORT, 'types_members requires member_name and member_type')
                END;

                INSERT INTO type_members(parent_type_id, member_name, member_type, size)
                VALUES (
                    COALESCE(
                        (SELECT t.type_id FROM types t WHERE t.name = NEW.type_name LIMIT 1),
                        (SELECT t.type_id FROM types t WHERE t.ordinal = NEW.type_ordinal LIMIT 1)
                    ),
                    NEW.member_name,
                    NEW.member_type,
                    CASE
                        WHEN NEW.size IS NULL OR NEW.size <= 0 THEN 1
                        ELSE NEW.size
                    END
                );
            END
        )");

        db.exec(R"(
            CREATE TRIGGER IF NOT EXISTS types_members_update
            INSTEAD OF UPDATE ON types_members
            BEGIN
                SELECT CASE
                    WHEN COALESCE(NEW.type_ordinal, OLD.type_ordinal) <> OLD.type_ordinal
                      OR COALESCE(NEW.type_name, OLD.type_name) <> OLD.type_name
                      OR COALESCE(NEW.member_index, OLD.member_index) <> OLD.member_index
                      OR COALESCE(NEW.offset, OLD.offset) <> OLD.offset
                      OR COALESCE(NEW.offset_bits, OLD.offset_bits) <> OLD.offset_bits
                      OR COALESCE(NEW.size, OLD.size) <> OLD.size
                      OR COALESCE(NEW.size_bits, OLD.size_bits) <> OLD.size_bits
                      OR COALESCE(NEW.is_bitfield, OLD.is_bitfield) <> OLD.is_bitfield
                      OR COALESCE(NEW.is_baseclass, OLD.is_baseclass) <> OLD.is_baseclass
                      OR COALESCE(NEW.comment, OLD.comment) <> OLD.comment
                      OR COALESCE(NEW.mt_is_struct, OLD.mt_is_struct) <> OLD.mt_is_struct
                      OR COALESCE(NEW.mt_is_union, OLD.mt_is_union) <> OLD.mt_is_union
                      OR COALESCE(NEW.mt_is_enum, OLD.mt_is_enum) <> OLD.mt_is_enum
                      OR COALESCE(NEW.mt_is_ptr, OLD.mt_is_ptr) <> OLD.mt_is_ptr
                      OR COALESCE(NEW.mt_is_array, OLD.mt_is_array) <> OLD.mt_is_array
                      OR COALESCE(NEW.member_type_ordinal, OLD.member_type_ordinal) <> OLD.member_type_ordinal
                    THEN RAISE(ABORT, 'types_members only supports updating member_name/member_type')
                END;

                UPDATE type_members
                SET
                    member_name = COALESCE(NEW.member_name, OLD.member_name),
                    member_type = COALESCE(NEW.member_type, OLD.member_type)
                WHERE parent_type_id = COALESCE(
                    (SELECT t.type_id FROM types t WHERE t.name = OLD.type_name LIMIT 1),
                    (SELECT t.type_id FROM types t WHERE t.ordinal = OLD.type_ordinal LIMIT 1),
                    (SELECT t.type_id FROM types t WHERE t.name = NEW.type_name LIMIT 1),
                    (SELECT t.type_id FROM types t WHERE t.ordinal = NEW.type_ordinal LIMIT 1)
                )
                AND ordinal = COALESCE(OLD.member_index, NEW.member_index);
            END
        )");

        db.exec(R"(
            CREATE TRIGGER IF NOT EXISTS types_members_delete
            INSTEAD OF DELETE ON types_members
            BEGIN
                DELETE FROM type_members
                WHERE parent_type_id = COALESCE(
                    (SELECT t.type_id FROM types t WHERE t.name = OLD.type_name LIMIT 1),
                    (SELECT t.type_id FROM types t WHERE t.ordinal = OLD.type_ordinal LIMIT 1)
                )
                AND ordinal = OLD.member_index;
            END
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_enum_values AS
            SELECT
                COALESCE(t.ordinal, CAST(NULLIF(e.type_id, '') AS INTEGER), 0) AS type_ordinal,
                COALESCE(t.name, e.type_id) AS type_name,
                e.ordinal AS value_index,
                e.name AS value_name,
                e.value AS value,
                CASE
                    WHEN e.value < 0 THEN 0
                    ELSE e.value
                END AS uvalue,
                '' AS comment
            FROM type_enum_members e
            LEFT JOIN types t ON t.type_id = e.type_id
        )");

        db.exec(R"(
            CREATE TRIGGER IF NOT EXISTS types_enum_values_insert
            INSTEAD OF INSERT ON types_enum_values
            BEGIN
                SELECT CASE
                    WHEN COALESCE(
                        (SELECT t.type_id FROM types t WHERE t.name = NEW.type_name LIMIT 1),
                        (SELECT t.type_id FROM types t WHERE t.ordinal = NEW.type_ordinal LIMIT 1)
                    ) IS NULL
                    THEN RAISE(ABORT, 'types_enum_values requires valid type_name or type_ordinal')
                END;

                INSERT INTO type_enum_members(type_id, name, value)
                VALUES (
                    COALESCE(
                        (SELECT t.type_id FROM types t WHERE t.name = NEW.type_name LIMIT 1),
                        (SELECT t.type_id FROM types t WHERE t.ordinal = NEW.type_ordinal LIMIT 1)
                    ),
                    COALESCE(NEW.value_name, ''),
                    COALESCE(NEW.value, NEW.uvalue, 0)
                );
            END
        )");

        db.exec(R"(
            CREATE TRIGGER IF NOT EXISTS types_enum_values_update
            INSTEAD OF UPDATE ON types_enum_values
            BEGIN
                UPDATE type_enum_members
                SET
                    name = COALESCE(NEW.value_name, OLD.value_name),
                    value = COALESCE(NEW.value, NEW.uvalue, OLD.value)
                WHERE type_id = COALESCE(
                    (SELECT t.type_id FROM types t WHERE t.name = OLD.type_name LIMIT 1),
                    (SELECT t.type_id FROM types t WHERE t.ordinal = OLD.type_ordinal LIMIT 1),
                    (SELECT t.type_id FROM types t WHERE t.name = NEW.type_name LIMIT 1),
                    (SELECT t.type_id FROM types t WHERE t.ordinal = NEW.type_ordinal LIMIT 1)
                )
                AND ordinal = COALESCE(OLD.value_index, NEW.value_index);
            END
        )");

        db.exec(R"(
            CREATE TRIGGER IF NOT EXISTS types_enum_values_delete
            INSTEAD OF DELETE ON types_enum_values
            BEGIN
                DELETE FROM type_enum_members
                WHERE type_id = COALESCE(
                    (SELECT t.type_id FROM types t WHERE t.name = OLD.type_name LIMIT 1),
                    (SELECT t.type_id FROM types t WHERE t.ordinal = OLD.type_ordinal LIMIT 1)
                )
                AND ordinal = OLD.value_index;
            END
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_v_structs AS
            SELECT *
            FROM types
            WHERE lower(kind) = 'struct'
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_v_unions AS
            SELECT *
            FROM types
            WHERE lower(kind) = 'union'
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_v_enums AS
            SELECT *
            FROM types
            WHERE lower(kind) = 'enum'
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_v_typedefs AS
            SELECT *
            FROM types
            WHERE lower(kind) IN ('typedef', 'alias')
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS types_v_funcs AS
            SELECT *
            FROM types
            WHERE lower(kind) IN ('func', 'function')
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS local_types AS
            SELECT
                ordinal,
                name,
                declaration AS type,
                CASE WHEN lower(kind) = 'struct' THEN 1 ELSE 0 END AS is_struct,
                CASE WHEN lower(kind) = 'enum' THEN 1 ELSE 0 END AS is_enum,
                CASE WHEN lower(kind) IN ('typedef', 'alias') THEN 1 ELSE 0 END AS is_typedef
            FROM types
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS jump_entities AS
            WITH function_entities AS (
                SELECT
                    f.name AS name,
                    'function' AS kind,
                    f.address AS address,
                    CAST(NULL AS INTEGER) AS ordinal,
                    CAST(NULL AS TEXT) AS parent_name,
                    f.name AS full_name
                FROM funcs f
            ),
            label_entities AS (
                SELECT
                    n.name AS name,
                    'label' AS kind,
                    n.address AS address,
                    CAST(NULL AS INTEGER) AS ordinal,
                    CAST(NULL AS TEXT) AS parent_name,
                    n.name AS full_name
                FROM names n
                WHERE lower(COALESCE(n.symbol_kind, '')) NOT IN ('function', 'func', 'import', 'export')
            ),
            segment_entities AS (
                SELECT
                    s.name AS name,
                    'segment' AS kind,
                    s.start_ea AS address,
                    CAST(NULL AS INTEGER) AS ordinal,
                    CAST(NULL AS TEXT) AS parent_name,
                    s.name AS full_name
                FROM segments s
            ),
            type_entities AS (
                SELECT
                    t.name AS name,
                    CASE
                        WHEN lower(t.kind) IN ('struct', 'union', 'enum') THEN lower(t.kind)
                        ELSE 'type'
                    END AS kind,
                    CAST(NULL AS INTEGER) AS address,
                    COALESCE(CAST(NULLIF(t.type_id, '') AS INTEGER), 0) AS ordinal,
                    CAST(NULL AS TEXT) AS parent_name,
                    t.name AS full_name
                FROM types t
            ),
            member_entities AS (
                SELECT
                    tm.member_name AS name,
                    'member' AS kind,
                    CAST(NULL AS INTEGER) AS address,
                    tm.type_ordinal AS ordinal,
                    tm.type_name AS parent_name,
                    tm.type_name || '.' || tm.member_name AS full_name
                FROM types_members tm
            ),
            enum_member_entities AS (
                SELECT
                    te.value_name AS name,
                    'enum_member' AS kind,
                    CAST(NULL AS INTEGER) AS address,
                    te.type_ordinal AS ordinal,
                    te.type_name AS parent_name,
                    te.type_name || '.' || te.value_name AS full_name
                FROM types_enum_values te
            )
            SELECT * FROM function_entities
            UNION ALL
            SELECT * FROM label_entities
            UNION ALL
            SELECT * FROM segment_entities
            UNION ALL
            SELECT * FROM type_entities
            UNION ALL
            SELECT * FROM member_entities
            UNION ALL
            SELECT * FROM enum_member_entities
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS function_signatures AS
            WITH function_signatures_only AS (
                SELECT
                    sig_id,
                    owner_addr,
                    name,
                    prototype,
                    calling_convention,
                    return_type,
                    param_count,
                    is_variadic
                FROM signatures
                WHERE owner_kind = 'function'
            )
            SELECT
                s.sig_id,
                s.owner_addr AS func_addr,
                COALESCE(NULLIF(s.name, ''), printf('sub_%X', s.owner_addr)) AS func_name,
                s.prototype,
                s.calling_convention,
                s.return_type,
                s.param_count,
                s.is_variadic
            FROM function_signatures_only s
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS function_params_expanded AS
            SELECT
                p.func_addr,
                COALESCE(f.name, printf('sub_%X', p.func_addr)) AS func_name,
                p.ordinal,
                p.param_name,
                p.param_type,
                p.storage,
                p.is_user_named
            FROM function_params p
            LEFT JOIN funcs f ON f.address = p.func_addr
            ORDER BY p.func_addr, p.ordinal
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS function_frame_layout AS
            WITH local_agg AS (
                SELECT func_addr, COUNT(*) AS local_count, COALESCE(SUM(size), 0) AS local_bytes
                FROM function_locals
                GROUP BY func_addr
            ),
            param_agg AS (
                SELECT func_addr, COUNT(*) AS param_count
                FROM function_params
                GROUP BY func_addr
            )
            SELECT
                fr.func_addr,
                COALESCE(f.name, printf('sub_%X', fr.func_addr)) AS func_name,
                fr.frame_size,
                fr.arg_size,
                fr.local_size,
                fr.saved_reg_size,
                fr.stack_base_reg,
                fr.has_frame_pointer,
                COALESCE(pa.param_count, 0) AS param_count,
                COALESCE(la.local_count, 0) AS local_count,
                COALESCE(la.local_bytes, 0) AS local_bytes
            FROM function_frames fr
            LEFT JOIN funcs f ON f.address = fr.func_addr
            LEFT JOIN param_agg pa ON pa.func_addr = fr.func_addr
            LEFT JOIN local_agg la ON la.func_addr = fr.func_addr
            ORDER BY fr.func_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS stack_var_layout AS
            SELECT
                s.func_addr,
                COALESCE(f.name, printf('sub_%X', s.func_addr)) AS func_name,
                s.var_id,
                s.name,
                s.var_type,
                s.stack_offset,
                s.size,
                s.is_param,
                fr.frame_size
            FROM stack_vars s
            LEFT JOIN funcs f ON f.address = s.func_addr
            LEFT JOIN function_frames fr ON fr.func_addr = s.func_addr
            ORDER BY s.func_addr, s.stack_offset
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS register_var_summary AS
            SELECT
                r.func_addr,
                COALESCE(f.name, printf('sub_%X', r.func_addr)) AS func_name,
                r.reg_name,
                COUNT(*) AS var_count,
                SUM(CASE WHEN r.is_param = 1 THEN 1 ELSE 0 END) AS param_count
            FROM register_vars r
            LEFT JOIN funcs f ON f.address = r.func_addr
            GROUP BY r.func_addr, f.name, r.reg_name
            ORDER BY r.func_addr, r.reg_name
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS function_chunks_detailed AS
            SELECT
                c.func_addr,
                COALESCE(f.name, printf('sub_%X', c.func_addr)) AS func_name,
                c.chunk_id,
                c.start_ea,
                c.end_ea,
                (c.end_ea - c.start_ea) AS chunk_size,
                c.chunk_kind,
                c.is_primary
            FROM function_chunks c
            LEFT JOIN funcs f ON f.address = c.func_addr
            ORDER BY c.func_addr, c.start_ea
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS tail_call_edges AS
            SELECT
                t.src_func_addr,
                COALESCE(sf.name, printf('sub_%X', t.src_func_addr)) AS src_func_name,
                t.call_site,
                t.dst_addr,
                t.dst_func_addr,
                COALESCE(df.name, printf('sub_%X', t.dst_func_addr)) AS dst_func_name,
                t.tail_kind
            FROM tail_calls t
            LEFT JOIN funcs sf ON sf.address = t.src_func_addr
            LEFT JOIN funcs df ON df.address = t.dst_func_addr
            ORDER BY t.src_func_addr, t.call_site
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS project_settings AS
            SELECT
                p.property_key,
                p.property_value,
                p.property_scope
            FROM project_properties p
            UNION ALL
            SELECT
                o.option_key AS property_key,
                o.option_value AS property_value,
                o.option_scope AS property_scope
            FROM program_options o
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS analysis_pass_timeline AS
            SELECT
                a.pass_id,
                a.pass_name,
                a.status,
                a.started_unix,
                a.ended_unix,
                (a.ended_unix - a.started_unix) AS duration_sec,
                a.notes
            FROM analysis_passes a
            ORDER BY a.pass_id
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS transaction_log AS
            SELECT
                t.tx_id,
                t.tx_name,
                t.tx_kind,
                t.start_revision,
                t.end_revision,
                (t.end_revision - t.start_revision) AS revision_delta,
                t.committed
            FROM transactions t
            ORDER BY t.tx_id
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS relocation_map AS
            SELECT
                r.address,
                r.target_addr,
                r.reloc_type,
                r.width,
                r.symbol_name,
                COALESCE(n.name, r.symbol_name, printf('sub_%X', r.target_addr)) AS target_name
            FROM relocations r
            LEFT JOIN names n ON n.address = r.target_addr
            ORDER BY r.address
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS constant_hotspots AS
            SELECT
                c.func_addr,
                COALESCE(f.name, printf('sub_%X', c.func_addr)) AS func_name,
                COUNT(*) AS constant_count,
                MIN(c.value) AS min_value,
                MAX(c.value) AS max_value
            FROM constants c
            LEFT JOIN funcs f ON f.address = c.func_addr
            GROUP BY c.func_addr, f.name
            ORDER BY constant_count DESC, c.func_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS equate_catalog AS
            SELECT
                e.equate_id,
                e.name,
                e.value,
                e.width,
                e.domain
            FROM equates e
            ORDER BY e.domain, e.name
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS search_docs AS
            SELECT
                doc_id,
                domain,
                address,
                func_addr,
                LENGTH(text) AS text_len,
                substr(text, 1, 120) AS preview
            FROM text_index
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS search_terms AS
            SELECT
                term,
                domain,
                COUNT(*) AS doc_hits,
                SUM(hit_count) AS total_hits,
                MAX(rank) AS best_rank
            FROM search_index
            GROUP BY term, domain
            ORDER BY total_hits DESC, term
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS searchindex AS
            SELECT
                doc_id,
                term,
                domain,
                address,
                func_addr,
                hit_count,
                rank
            FROM search_index
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS xref_paths AS
            SELECT
                xi.from_ea,
                xi.to_ea,
                xi.kind,
                xi.src_func_addr,
                COALESCE(sf.name, printf('sub_%X', xi.src_func_addr)) AS src_func_name,
                xi.dst_func_addr,
                COALESCE(df.name, printf('sub_%X', xi.dst_func_addr)) AS dst_func_name,
                xi.is_code,
                xi.is_data
            FROM xref_index xi
            LEFT JOIN funcs sf ON sf.address = xi.src_func_addr
            LEFT JOIN funcs df ON df.address = xi.dst_func_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS xref_out_summary AS
            SELECT
                src_func_addr AS func_addr,
                COUNT(*) AS xref_out
            FROM xref_index
            WHERE src_func_addr != 0
            GROUP BY src_func_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS cfg_edges_detailed AS
            SELECT
                c.func_addr,
                COALESCE(f.name, printf('sub_%X', c.func_addr)) AS func_name,
                c.src_start_ea,
                c.dst_start_ea,
                c.edge_kind
            FROM cfg_edges c
            LEFT JOIN funcs f ON f.address = c.func_addr
            ORDER BY c.func_addr, c.src_start_ea, c.dst_start_ea
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS loop_summary AS
            SELECT
                l.func_addr,
                COALESCE(f.name, printf('sub_%X', l.func_addr)) AS func_name,
                COUNT(*) AS loop_count,
                MAX(l.depth) AS max_depth,
                COALESCE(SUM(l.block_count), 0) AS total_loop_blocks
            FROM loops l
            LEFT JOIN funcs f ON f.address = l.func_addr
            GROUP BY l.func_addr, f.name
            ORDER BY loop_count DESC, l.func_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS switch_summary AS
            SELECT
                s.func_addr,
                COALESCE(f.name, printf('sub_%X', s.func_addr)) AS func_name,
                COUNT(*) AS switch_sites,
                COALESCE(MAX(s.case_count), 0) AS max_cases,
                COALESCE(AVG(s.case_count), 0.0) AS avg_cases
            FROM switch_tables s
            LEFT JOIN funcs f ON f.address = s.func_addr
            GROUP BY s.func_addr, f.name
            ORDER BY switch_sites DESC, s.func_addr
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS dominator_tree AS
            SELECT
                d.func_addr,
                COALESCE(f.name, printf('sub_%X', d.func_addr)) AS func_name,
                d.node_ea,
                COALESCE(nn.name, printf('loc_%X', d.node_ea)) AS node_name,
                d.idom_ea,
                COALESCE(inm.name, printf('loc_%X', d.idom_ea)) AS idom_name,
                d.depth,
                d.is_entry
            FROM dominators d
            LEFT JOIN funcs f ON f.address = d.func_addr
            LEFT JOIN names nn ON nn.address = d.node_ea
            LEFT JOIN names inm ON inm.address = d.idom_ea
            ORDER BY d.func_addr, d.depth, d.node_ea
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS post_dominator_tree AS
            SELECT
                pd.func_addr,
                COALESCE(f.name, printf('sub_%X', pd.func_addr)) AS func_name,
                pd.node_ea,
                COALESCE(nn.name, printf('loc_%X', pd.node_ea)) AS node_name,
                pd.ipdom_ea,
                COALESCE(pinm.name, printf('loc_%X', pd.ipdom_ea)) AS ipdom_name,
                pd.depth,
                pd.is_exit
            FROM post_dominators pd
            LEFT JOIN funcs f ON f.address = pd.func_addr
            LEFT JOIN names nn ON nn.address = pd.node_ea
            LEFT JOIN names pinm ON pinm.address = pd.ipdom_ea
            ORDER BY pd.func_addr, pd.depth, pd.node_ea
        )");

        db.exec(R"(
            CREATE VIEW IF NOT EXISTS function_metrics_ranked AS
            SELECT
                s.func_addr,
                s.func_name,
                s.size,
                s.instruction_count,
                s.block_count,
                s.edge_count,
                s.cyclomatic_complexity,
                s.call_in_count,
                s.call_out_count,
                s.string_ref_count,
                s.token_count,
                s.hotness_score,
                DENSE_RANK() OVER (ORDER BY s.hotness_score DESC, s.func_addr) AS hot_rank
            FROM function_metrics_scored s
        )");
    }


}  // namespace ghidrasql::entities
