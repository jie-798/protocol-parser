# Examples CMakeLists.txt
cmake_minimum_required(VERSION 3.15)

# 示例程序列表
set(EXAMPLES
    live_capture
)

# npcap SDK路径
set(NPCAP_SDK_PATH "${CMAKE_SOURCE_DIR}/examples/lib/npcap-sdk-1.15")

# 为每个示例创建可执行文件
foreach(EXAMPLE ${EXAMPLES})
    add_executable(${EXAMPLE} ${EXAMPLE}.cpp)
    
    # 链接核心库
    target_link_libraries(${EXAMPLE} PRIVATE protocol_parser_core)
    
    # 设置包含目录
    target_include_directories(${EXAMPLE} PRIVATE 
        ${CMAKE_SOURCE_DIR}/include
        ${NPCAP_SDK_PATH}/Include
    )
    
    # 链接npcap库
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        # 64位
        target_link_libraries(${EXAMPLE} PRIVATE 
            ${NPCAP_SDK_PATH}/Lib/x64/wpcap.lib
            ${NPCAP_SDK_PATH}/Lib/x64/Packet.lib
        )
    else()
        # 32位
        target_link_libraries(${EXAMPLE} PRIVATE 
            ${NPCAP_SDK_PATH}/Lib/wpcap.lib
            ${NPCAP_SDK_PATH}/Lib/Packet.lib
        )
    endif()
    
    # 设置C++标准
    target_compile_features(${EXAMPLE} PRIVATE cxx_std_20)
    
    # 编译器特定设置
    if(MSVC)
        target_compile_options(${EXAMPLE} PRIVATE /W4 /O2)
    else()
        target_compile_options(${EXAMPLE} PRIVATE -Wall -Wextra -O3)
    endif()
    
    # 设置输出目录
    set_target_properties(${EXAMPLE} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin/examples
    )
endforeach()

# 安装示例程序（可选）
if(INSTALL_EXAMPLES)
    install(TARGETS ${EXAMPLES}
        RUNTIME DESTINATION bin/examples
    )
endif()