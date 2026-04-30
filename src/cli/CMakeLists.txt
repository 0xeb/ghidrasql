add_executable(ghidrasql-cli
    main.cpp
)

target_link_libraries(ghidrasql-cli PRIVATE ghidrasql::ghidrasql)

set_target_properties(ghidrasql-cli PROPERTIES
    OUTPUT_NAME "ghidrasql"
)

install(TARGETS ghidrasql-cli
    RUNTIME DESTINATION bin
)
