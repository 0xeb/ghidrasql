# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
#
# This file is licensed under the Human-Origin Source License v1.0.
# See LICENSE.
#
cmake_minimum_required(VERSION 3.26)
project(ghidrasql VERSION 0.0.6 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

option(GHIDRASQL_WITH_LIBGHIDRA "Build ghidrasql with libghidra C++ source adapters" ON)
option(GHIDRASQL_WITH_MCP "Build ghidrasql with MCP server support (fastmcpp)" ON)
option(GHIDRASQL_STATIC_MSVC_RUNTIME
    "Use the static MSVC runtime for non-Debug builds"
    ${MSVC})
set(GHIDRASQL_LIBGHIDRA_DIR "" CACHE PATH
    "Path to libghidra C++ SDK (libghidra/cpp/)")
set(GHIDRASQL_LIBXSQL_DIR "" CACHE PATH
    "Path to a local libxsql checkout (overrides external/libxsql and FetchContent)")

if(MSVC AND GHIDRASQL_STATIC_MSVC_RUNTIME)
    # Protobuf's protobuf_MSVC_STATIC_RUNTIME toggle is not config-specific,
    # so we use a uniform static CRT across all configs (including Debug).
    # FORCE ensures a stale cache value is overwritten on reconfigure.
    set(CMAKE_MSVC_RUNTIME_LIBRARY
        "MultiThreaded$<$<CONFIG:Debug>:Debug>"
        CACHE STRING "MSVC runtime library selection" FORCE)
endif()

if(MSVC)
    if(DEFINED CMAKE_MSVC_RUNTIME_LIBRARY AND CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "DLL")
        set(protobuf_MSVC_STATIC_RUNTIME OFF CACHE BOOL "" FORCE)
    else()
        set(protobuf_MSVC_STATIC_RUNTIME ON CACHE BOOL "" FORCE)
    endif()
endif()

set(XSQL_WITH_THINCLIENT ON CACHE BOOL "" FORCE)

include(FetchContent)

# Pre-fetch cpp-httplib v0.16.3 before libxsql (which would fetch v0.15.3).
# Both libxsql and libghidra share this target; v0.16.3 fixes Windows thread-join issues.
if(NOT TARGET httplib::httplib)
    # cpp-httplib is header-only, and more than one consumer here includes it.
    # Every translation unit in the final binary must see the SAME version AND the
    # same CPPHTTPLIB_*_SUPPORT feature macros, because the macros change the class
    # layouts (with OpenSSL+zlib found, httplib::ClientImpl is 1000 bytes; without
    # them, 784). Mixing two variants is an ODR violation the linker cannot
    # diagnose: it keeps one weak inline definition, and the other consumer then
    # reads and writes through the wrong offsets — including httplib's own mutexes,
    # which is why it presents as an abort inside pthread_mutex_lock.
    #
    # (a) Turn the optional features OFF so this target carries no feature macros.
    #     The libghidra RPC and the ghidrasql HTTP server are localhost plain HTTP.
    set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
    set(HTTPLIB_USE_ZLIB_IF_AVAILABLE    OFF CACHE BOOL "" FORCE)
    set(HTTPLIB_USE_BROTLI_IF_AVAILABLE  OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG        v0.16.3
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(httplib)
    # (b) Claim the `cpp_httplib` FetchContent name at the same version. fastmcpp
    #     declares that name at v0.15.3 and raw-includes it; first-declare-wins means
    #     it gets this source instead. SOURCE_SUBDIR names a directory that does not
    #     exist, so the project is populated without being add_subdirectory'd twice.
    FetchContent_Declare(cpp_httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG        v0.16.3
        GIT_SHALLOW    TRUE
        SOURCE_SUBDIR  .xsql-source-only
    )
    FetchContent_MakeAvailable(cpp_httplib)
endif()

if(TARGET xsql::xsql)
    message(STATUS "ghidrasql: Using xsql::xsql from parent project")
elseif(NOT GHIDRASQL_LIBXSQL_DIR STREQUAL ""
        AND EXISTS "${GHIDRASQL_LIBXSQL_DIR}/CMakeLists.txt")
    add_subdirectory("${GHIDRASQL_LIBXSQL_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/libxsql")
    message(STATUS "ghidrasql: Added libxsql from GHIDRASQL_LIBXSQL_DIR=${GHIDRASQL_LIBXSQL_DIR}")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/external/libxsql/CMakeLists.txt")
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/external/libxsql" "${CMAKE_CURRENT_BINARY_DIR}/libxsql")
    message(STATUS "ghidrasql: Added libxsql from ghidrasql/external/libxsql")
else()
    message(STATUS "ghidrasql: Fetching libxsql from GitHub (shallow clone)...")
    # libxsql is a first-party dep we own — track main so ghidrasql builds
    # against the latest (only third-party deps like cpp-httplib are pinned).
    FetchContent_Declare(libxsql
        GIT_REPOSITORY https://github.com/0xeb/libxsql.git
        GIT_TAG        main
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(libxsql)
endif()

if(NOT GHIDRASQL_WITH_LIBGHIDRA)
    message(FATAL_ERROR
        "ghidrasql is API-host-only: GHIDRASQL_WITH_LIBGHIDRA must be ON")
endif()

# ============================================================================
# MCP Support (optional)
# ============================================================================
if(GHIDRASQL_WITH_MCP)
    message(STATUS "ghidrasql: Building with MCP support via fastmcpp")

    if(NOT TARGET fastmcpp_core)
        set(FASTMCPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_BUILD_CLI OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_ENABLE_POST_STREAMING OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_ENABLE_SAMPLING_HTTP_HANDLERS OFF CACHE BOOL "" FORCE)
        set(FASTMCPP_FETCH_CURL OFF CACHE BOOL "" FORCE)

        message(STATUS "ghidrasql: Fetching fastmcpp from GitHub (tracking main)...")
        # Track the branch tip of fastmcpp — a FIRST-PARTY dependency we own and
        # maintain — so every libxsql consumer (ghidrasql/idasql/r2sql/bnsql) builds
        # against the latest fixes. (Only third-party deps like cpp-httplib are
        # pinned to a fixed tag.) GIT_SHALLOW keeps the clone cheap;
        # FETCHCONTENT_UPDATES_DISCONNECTED must stay OFF (the default) for the tip
        # to actually refresh on reconfigure.
        FetchContent_Declare(fastmcpp
            GIT_REPOSITORY https://github.com/0xeb/fastmcpp.git
            GIT_TAG        main
            GIT_SHALLOW    TRUE
        )
        FetchContent_MakeAvailable(fastmcpp)
    endif()

    if(MSVC AND TARGET fastmcpp_core)
        target_compile_options(fastmcpp_core PRIVATE /MP)
    endif()

    # fastmcpp_core is a static library that gets linked into the ghidrasql
    # CLI / plugin (shared lib on Linux). Enable PIC so the link succeeds.
    if(TARGET fastmcpp_core)
        set_property(TARGET fastmcpp_core PROPERTY POSITION_INDEPENDENT_CODE ON)
    endif()

    # (c) Give fastmcpp the same cpp-httplib feature macros everything else uses.
    #     Unlike (a)/(b) above this runs even when httplib::httplib came from an
    #     enclosing project — the vendored case, where that parent may well have
    #     enabled OpenSSL/zlib and we cannot turn them off. Linking the target
    #     propagates whatever macros it carries, so the two always agree.
    #     Harmless once fastmcpp itself consumes httplib::httplib directly.
    if(TARGET fastmcpp_core AND TARGET httplib::httplib)
        target_link_libraries(fastmcpp_core PUBLIC httplib::httplib)
    endif()
endif()

if(GHIDRASQL_WITH_LIBGHIDRA AND NOT TARGET libghidra::client)
    set(_libghidra_hint_dir "${GHIDRASQL_LIBGHIDRA_DIR}")
    if(_libghidra_hint_dir STREQUAL "")
        get_filename_component(_parent "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)
        if(EXISTS "${_parent}/libghidra/cpp/CMakeLists.txt")
            set(_libghidra_hint_dir "${_parent}/libghidra/cpp")
        endif()
    endif()

    set(_libghidra_package_hints "")
    if(NOT _libghidra_hint_dir STREQUAL "")
        list(APPEND _libghidra_package_hints
            "${_libghidra_hint_dir}"
            "${_libghidra_hint_dir}/lib/cmake/libghidra"
            "${_libghidra_hint_dir}/cmake")
    endif()
    find_package(libghidra CONFIG QUIET HINTS ${_libghidra_package_hints})
endif()

if(GHIDRASQL_WITH_LIBGHIDRA AND NOT TARGET libghidra::client)
    set(_libghidra_cpp_dir "${GHIDRASQL_LIBGHIDRA_DIR}")
    if(_libghidra_cpp_dir STREQUAL "")
        get_filename_component(_parent "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)
        if(EXISTS "${_parent}/libghidra/cpp/CMakeLists.txt")
            set(_libghidra_cpp_dir "${_parent}/libghidra/cpp")
        endif()
    endif()
    if(NOT _libghidra_cpp_dir STREQUAL "" AND EXISTS "${_libghidra_cpp_dir}/CMakeLists.txt")
        add_subdirectory("${_libghidra_cpp_dir}" "${CMAKE_CURRENT_BINARY_DIR}/libghidra-cpp")
        message(STATUS "ghidrasql: Added libghidra client from ${_libghidra_cpp_dir}")
    endif()
endif()

if(GHIDRASQL_WITH_LIBGHIDRA AND NOT TARGET libghidra::client)
    message(FATAL_ERROR
        "ghidrasql requires libghidra::client. Set GHIDRASQL_LIBGHIDRA_DIR to either "
        "a libghidra/cpp source tree or a libghidra install prefix/package directory.")
endif()

add_subdirectory(src)
