add_executable(protocol_parser_basic_example
    basic_packet_parse.cpp
)

target_link_libraries(protocol_parser_basic_example
    PRIVATE
        protocol_parser_core
)

set_target_properties(protocol_parser_basic_example PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples
)
