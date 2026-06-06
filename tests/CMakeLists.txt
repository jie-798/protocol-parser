add_executable(protocol_parser_tests
    basic_tests.cpp
)

target_link_libraries(protocol_parser_tests
    PRIVATE
        protocol_parser_core
)

add_test(NAME protocol_parser_tests COMMAND protocol_parser_tests)
