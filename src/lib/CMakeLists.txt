add_library(ghidrasql STATIC
    src/commands.cpp
    src/database.cpp
    src/entities_detail.cpp
    src/entities_tables.cpp
    src/entities_views.cpp
    src/functions.cpp
    src/http.cpp
    src/source.cpp
    src/source_factories.cpp
    src/source_libghidra.cpp
    src/source_callbacks.cpp
)
add_library(ghidrasql::ghidrasql ALIAS ghidrasql)

target_compile_features(ghidrasql PUBLIC cxx_std_20)
target_compile_definitions(ghidrasql PUBLIC
    GHIDRASQL_VERSION="${PROJECT_VERSION}"
)
target_compile_options(ghidrasql PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/bigobj>
)

target_include_directories(ghidrasql
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(ghidrasql PUBLIC xsql::xsql)

if(GHIDRASQL_WITH_LIBGHIDRA AND TARGET libghidra::client)
    target_compile_definitions(ghidrasql PUBLIC GHIDRASQL_HAS_LIBGHIDRA)
    target_link_libraries(ghidrasql PUBLIC libghidra::client)
endif()

install(TARGETS ghidrasql
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(FILES
    include/ghidrasql/ghidrasql.hpp
    include/ghidrasql/source.hpp
    DESTINATION include/ghidrasql
)
