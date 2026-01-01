# 示例程序构建配置 - 现代化真实网卡抓包版本

# 示例程序列表
set(EXAMPLES
    modern_live_capture        # 现代化真实网卡抓包GUI版本
    wireshark_style_gui        # Wireshark风格现代化GUI版本
    performance_benchmark      # 性能基准测试
)

# 为每个示例创建可执行文件
foreach(EXAMPLE ${EXAMPLES})
    add_executable(${EXAMPLE} ${EXAMPLE}.cpp)

    # 链接核心库
    target_link_libraries(${EXAMPLE} PRIVATE protocol_parser_core)

    # 设置C++标准
    target_compile_features(${EXAMPLE} PRIVATE cxx_std_23)

    # 编译器设置
    if(MSVC)
        target_compile_options(${EXAMPLE} PRIVATE /W4 /O2)
    else()
        target_compile_options(${EXAMPLE} PRIVATE -Wall -Wextra -O3)
    endif()

    # 设置输出目录
    set_target_properties(${EXAMPLE} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples
        WIN32_EXECUTABLE TRUE
    )
endforeach()