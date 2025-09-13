# 核心库源文件
set(CORE_SOURCES
    core/buffer_view.cpp
)

# 解析器源文件
set(PARSER_SOURCES
    # 基础解析器
    parsers/base_parser.cpp
    
    # 数据链路层解析器
    parsers/datalink/ethernet_parser.cpp
    parsers/datalink/arp_parser.cpp
    
    # 网络层解析器
    parsers/network/ipv4_parser.cpp
    parsers/network/ipv6_parser.cpp
    parsers/network/icmp_parser.cpp
    parsers/network/icmpv6_parser.cpp
    
    # 传输层解析器
    parsers/transport/tcp_parser.cpp
    parsers/transport/udp_parser.cpp
    parsers/transport/sctp_parser.cpp
    
    # 应用层解析器
    parsers/application/dns_parser.cpp
    parsers/application/http_parser.cpp
    parsers/application/https_parser.cpp
    parsers/application/ftp_parser.cpp
    parsers/application/ssh_parser.cpp
    parsers/application/telnet_parser.cpp
    parsers/application/pop3_parser.cpp
    parsers/application/dhcp_parser.cpp
    parsers/application/snmp_parser.cpp
)

# 统计和监控源文件
set(STATISTICS_SOURCES
    statistics/traffic_statistics.cpp
    # monitoring/performance_monitor.cpp
)

# 工具源文件
set(UTIL_SOURCES
    utils/network_utils.cpp
    # utils/simd_utils.cpp
    # utils/checksum.cpp
)

# 创建核心库
add_library(protocol_parser_core STATIC
    ${CORE_SOURCES}
    ${PARSER_SOURCES}
    ${STATISTICS_SOURCES}
    ${UTIL_SOURCES}
)

# 设置目标属性
target_include_directories(protocol_parser_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# 链接依赖
target_link_libraries(protocol_parser_core
    PUBLIC
        Threads::Threads
)

# 编译器特定优化
if(MSVC)
    target_compile_options(protocol_parser_core PRIVATE
        /O2 /Oi /Ot /Oy /GL
    )
    target_link_options(protocol_parser_core PRIVATE
        /LTCG
    )
else()
    target_compile_options(protocol_parser_core PRIVATE
        -O3 -flto -ffast-math
    )
    target_link_options(protocol_parser_core PRIVATE
        -flto
    )
endif()

# 安装规则
install(TARGETS protocol_parser_core
    EXPORT protocol_parser_targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)