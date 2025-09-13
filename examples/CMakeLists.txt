# 示例程序构建配置

# 示例程序列表
set(EXAMPLES
    live_capture
    advanced_features_demo
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
    )
endforeach()

# live_capture需要特殊的npcap支持
if(WIN32 AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/lib/npcap-sdk-1.15")
    set(NPCAP_SDK_PATH "${CMAKE_CURRENT_SOURCE_DIR}/lib/npcap-sdk-1.15")
    
    target_include_directories(live_capture PRIVATE 
        ${NPCAP_SDK_PATH}/Include
    )
    
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        # 64位
        target_link_libraries(live_capture PRIVATE 
            ${NPCAP_SDK_PATH}/Lib/x64/wpcap.lib
            ${NPCAP_SDK_PATH}/Lib/x64/Packet.lib
        )
    else()
        # 32位
        target_link_libraries(live_capture PRIVATE 
            ${NPCAP_SDK_PATH}/Lib/wpcap.lib
            ${NPCAP_SDK_PATH}/Lib/Packet.lib
        )
    endif()
endif()