# 协议解析器核心库构建配置

# 收集所有源文件
file(GLOB_RECURSE CORE_SOURCES
    "core/*.cpp"
    "parsers/*.cpp"
    "statistics/*.cpp"
    "detection/*.cpp"
    "utils/*.cpp"
    "ai/*.cpp"
)

# 添加新增的高级组件
file(GLOB_RECURSE SECURITY_SOURCES
    "parsers/security/*.cpp"
)

file(GLOB_RECURSE INDUSTRIAL_SOURCES
    "parsers/industrial/*.cpp"
)

file(GLOB_RECURSE AI_SOURCES
    "ai/*.cpp"
)

# 合并所有源文件
set(ALL_SOURCES ${CORE_SOURCES} ${SECURITY_SOURCES} ${INDUSTRIAL_SOURCES} ${AI_SOURCES})

# 排除暂未实现的文件
list(FILTER ALL_SOURCES EXCLUDE REGEX ".*monitoring.*")

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