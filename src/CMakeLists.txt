# 协议解析器核心库构建配置

# 核心组件
file(GLOB_RECURSE CORE_SOURCES
    "core/buffer_view.cpp"
    "core/buffer_pool.cpp"
    "core/tcp_reassembler.cpp"
)

# 工具类
file(GLOB_RECURSE UTILS_SOURCES
    "utils/*.cpp"
)

# 监控组件
file(GLOB_RECURSE MONITORING_SOURCES
    "monitoring/*.cpp"
)

# 协议解析器
file(GLOB_RECURSE PARSER_SOURCES
    "parsers/**/*.cpp"
)

# 检测和AI组件
file(GLOB_RECURSE DETECTION_SOURCES
    "detection/*.cpp"
    "ai/*.cpp"
)

# 合并所有源文件
set(ALL_SOURCES
    ${CORE_SOURCES}
    ${UTILS_SOURCES}
    ${MONITORING_SOURCES}
    ${PARSER_SOURCES}
    ${DETECTION_SOURCES}
)

# 创建核心库
add_library(protocol_parser_core STATIC ${ALL_SOURCES})

# 设置目标属性
target_include_directories(protocol_parser_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# 设置C++标准
target_compile_features(protocol_parser_core PUBLIC cxx_std_23)

# 链接依赖
target_link_libraries(protocol_parser_core
    PUBLIC
        Threads::Threads
)

# 编译器特定优化
if(MSVC)
    target_compile_options(protocol_parser_core PRIVATE
        /O2 /Oi /Ot /Oy /GL /fp:fast
    )
    target_link_options(protocol_parser_core PRIVATE
        /LTCG
    )
else()
    target_compile_options(protocol_parser_core PRIVATE
        -O3 -flto -ffast-math -funroll-loops
    )
    target_link_options(protocol_parser_core PRIVATE
        -flto
    )
endif()

# Windows特定设置
if(WIN32)
    target_link_libraries(protocol_parser_core PRIVATE ws2_32)
endif()

# 设置编译定义
target_compile_definitions(protocol_parser_core PRIVATE
    PROTOCOL_PARSER_BUILDING
    $<$<CONFIG:Debug>:PROTOCOL_PARSER_DEBUG>
    $<$<CONFIG:Release>:PROTOCOL_PARSER_RELEASE>
)

# 安装规则
install(TARGETS protocol_parser_core
    EXPORT protocol_parser_targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)