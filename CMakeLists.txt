cmake_minimum_required(VERSION 3.20)
project(ghidrasql VERSION 0.0.2 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
endif()

option(GHIDRASQL_WITH_LIBGHIDRA "Build ghidrasql with libghidra C++ source adapters" ON)
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
    FetchContent_Declare(httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG        v0.16.3
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(httplib)
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
    FetchContent_Declare(libxsql
        GIT_REPOSITORY https://github.com/0xeb/libxsql.git
        GIT_TAG        v1.0.8
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(libxsql)
endif()

if(NOT GHIDRASQL_WITH_LIBGHIDRA)
    message(FATAL_ERROR
        "ghidrasql is API-host-only: GHIDRASQL_WITH_LIBGHIDRA must be ON")
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
