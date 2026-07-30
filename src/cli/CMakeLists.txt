# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
#
add_executable(ghidrasql-cli
    main.cpp
)

target_link_libraries(ghidrasql-cli PRIVATE ghidrasql::ghidrasql)

if(GHIDRASQL_WITH_MCP)
    target_sources(ghidrasql-cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common/mcp_server.cpp
    )
    target_include_directories(ghidrasql-cli PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../common
    )
    target_link_libraries(ghidrasql-cli PRIVATE fastmcpp_core)
    target_compile_definitions(ghidrasql-cli PRIVATE GHIDRASQL_HAS_MCP=1)
endif()

set_target_properties(ghidrasql-cli PROPERTIES
    OUTPUT_NAME "ghidrasql"
)

install(TARGETS ghidrasql-cli
    RUNTIME DESTINATION bin
)
