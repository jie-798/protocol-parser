# 协议解析器核心库构建配置

# 创建核心库（源文件通过 target_sources 添加）
add_library(protocol_parser_core STATIC)

# 核心组件
target_sources(protocol_parser_core PRIVATE
    "core/buffer_view.cpp"
    "core/buffer_pool.cpp"
    "core/tcp_reassembler.cpp"
)

# 工具类
target_sources(protocol_parser_core PRIVATE
    "utils/network_utils.cpp"
    "utils/simd_utils.cpp"
)

# 监控组件
target_sources(protocol_parser_core PRIVATE
    "monitoring/performance_monitor.cpp"
)

# 协议解析器
target_sources(protocol_parser_core PRIVATE
    "parsers/base_parser.cpp"
    "parsers/application/http_parser.cpp"
    "parsers/application/https_parser.cpp"
    "parsers/application/ftp_parser.cpp"
    "parsers/application/ssh_parser.cpp"
    "parsers/application/dns_parser.cpp"
    "parsers/application/pop3_parser.cpp"
    "parsers/application/telnet_parser.cpp"
    "parsers/application/snmp_parser.cpp"
    "parsers/application/dhcp_parser.cpp"
    "parsers/application/grpc_parser.cpp"
    "parsers/application/websocket_parser.cpp"
    "parsers/application/sip_parser.cpp"
    "parsers/application/mqtt_parser.cpp"
    "parsers/datalink/arp_parser.cpp"
    "parsers/datalink/ethernet_parser.cpp"
    "parsers/network/icmp_parser.cpp"
    "parsers/network/icmpv6_parser.cpp"
    "parsers/network/ipv4_parser.cpp"
    "parsers/network/ipv6_parser.cpp"
    "parsers/transport/quic_parser.cpp"
    "parsers/transport/rtp_parser.cpp"
    "parsers/transport/tcp_parser.cpp"
    "parsers/transport/udp_parser.cpp"
    "parsers/transport/sctp_parser.cpp"
    "parsers/security/tls_deep_inspector.cpp"
    "parsers/industrial/modbus_deep_analyzer.cpp"
    "parsers/industrial/dnp3_deep_analyzer.cpp"
    "parsers/signaling/diameter_parser.cpp"
    "parsers/signaling/gtppv2_parser.cpp"
    "parsers/signaling/h323_parser.cpp"
    "parsers/signaling/m3ua_parser.cpp"
    "parsers/signaling/ngap_parser.cpp"
    "parsers/signaling/radius_parser.cpp"
    "parsers/signaling/s1ap_parser.cpp"
    "parsers/signaling/x2ap_parser.cpp"
)

# 检测、AI和统计组件
target_sources(protocol_parser_core PRIVATE
    "detection/protocol_detection.cpp"
    "detection/protocol_detector.cpp"
    "ai/protocol_detector.cpp"
    "statistics/traffic_statistics.cpp"
)
add_library(protocol_parser::core ALIAS protocol_parser_core)
set_target_properties(protocol_parser_core PROPERTIES EXPORT_NAME core)

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
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/Oi>
        $<$<CONFIG:Release>:/Ot>
        $<$<CONFIG:Release>:/Oy>
        $<$<CONFIG:Release>:/GL>
        $<$<CONFIG:Release>:/arch:AVX2>
        $<$<CONFIG:Release>:/fp:fast>
    )
    target_link_options(protocol_parser_core PUBLIC
        $<$<CONFIG:Release>:/LTCG>
    )
else()
    target_compile_options(protocol_parser_core PRIVATE
        $<$<CONFIG:Release>:-O3 -mavx2 -mpclmul -msse4.2>
        $<$<CONFIG:Release>:-flto>
        $<$<CONFIG:Release>:-ffast-math>
        $<$<CONFIG:Release>:-funroll-loops>
    )
    target_link_options(protocol_parser_core PUBLIC
        $<$<CONFIG:Release>:-flto>
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
include(CMakePackageConfigHelpers)

install(TARGETS protocol_parser_core
    EXPORT protocol_parser_targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/
    DESTINATION include
)

install(EXPORT protocol_parser_targets
    FILE protocol_parser_targets.cmake
    NAMESPACE protocol_parser::
    DESTINATION lib/cmake/protocol_parser
)

install(EXPORT protocol_parser_targets
    FILE protocol_parser_targets.cmake
    NAMESPACE protocol_parser::
    DESTINATION lib/cmake/ProtocolParser
)

set(PROTOCOL_PARSER_CONFIG_CONTENT
"include(CMakeFindDependencyMacro)\nfind_dependency(Threads)\ninclude(\${CMAKE_CURRENT_LIST_DIR}/protocol_parser_targets.cmake)\n"
)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/protocol_parserConfig.cmake
    "${PROTOCOL_PARSER_CONFIG_CONTENT}"
)
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/ProtocolParserConfig.cmake
    "${PROTOCOL_PARSER_CONFIG_CONTENT}"
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/protocol_parserConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/ProtocolParserConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/protocol_parserConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/protocol_parserConfigVersion.cmake
    DESTINATION lib/cmake/protocol_parser
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/ProtocolParserConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/ProtocolParserConfigVersion.cmake
    DESTINATION lib/cmake/ProtocolParser
)