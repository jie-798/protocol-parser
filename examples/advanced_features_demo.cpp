#include <iostream>
#include <vector>
#include <memory>
#include <chrono>
#include <thread>
#include <random>

// 包含新增的解析器和统计功能
#include "parsers/application/dhcp_parser.hpp"
#include "parsers/application/snmp_parser.hpp"
#include "statistics/traffic_statistics.hpp"
#include "monitoring/performance_monitor.hpp"

using namespace ProtocolParser;
using namespace std::chrono_literals;

// 生成模拟DHCP数据包
std::vector<uint8_t> generate_dhcp_packet() {
    std::vector<uint8_t> packet;
    
    // DHCP头部 (最小236字节)
    packet.resize(236, 0);
    
    // 基本DHCP字段
    packet[0] = 0x01;  // BOOTREQUEST
    packet[1] = 0x01;  // Ethernet
    packet[2] = 0x06;  // Hardware length
    packet[3] = 0x00;  // Hops
    
    // 事务ID (随机)
    std::random_device rd;
    std::mt19937 gen(rd());
    uint32_t xid = gen();
    *reinterpret_cast<uint32_t*>(&packet[4]) = htonl(xid);
    
    // 添加DHCP Magic Cookie
    packet.push_back(0x63);
    packet.push_back(0x82);
    packet.push_back(0x53);
    packet.push_back(0x63);
    
    // 添加DHCP消息类型选项 (DHCP Discover)
    packet.push_back(53);  // Option type
    packet.push_back(1);   // Length
    packet.push_back(1);   // DHCP Discover
    
    // 结束选项
    packet.push_back(255); // End option
    
    return packet;
}

// 生成模拟SNMP数据包
std::vector<uint8_t> generate_snmp_packet() {
    std::vector<uint8_t> packet;
    
    // 简单的SNMP v1 GET请求
    // BER编码的SEQUENCE
    packet.push_back(0x30); // SEQUENCE
    packet.push_back(0x26); // Length (38 bytes)
    
    // Version (INTEGER 0 for SNMPv1)
    packet.push_back(0x02); // INTEGER
    packet.push_back(0x01); // Length
    packet.push_back(0x00); // Value (0)
    
    // Community string "public"
    packet.push_back(0x04); // OCTET STRING
    packet.push_back(0x06); // Length
    packet.insert(packet.end(), {'p', 'u', 'b', 'l', 'i', 'c'});
    
    // GET Request PDU
    packet.push_back(0xa0); // GET Request
    packet.push_back(0x19); // Length
    
    // Request ID
    packet.push_back(0x02); // INTEGER
    packet.push_back(0x01); // Length
    packet.push_back(0x01); // Value
    
    // Error Status
    packet.push_back(0x02); // INTEGER
    packet.push_back(0x01); // Length
    packet.push_back(0x00); // Value (no error)
    
    // Error Index
    packet.push_back(0x02); // INTEGER
    packet.push_back(0x01); // Length
    packet.push_back(0x00); // Value
    
    // Variable bindings (empty for this example)
    packet.push_back(0x30); // SEQUENCE
    packet.push_back(0x0b); // Length
    
    // Single varbind
    packet.push_back(0x30); // SEQUENCE
    packet.push_back(0x09); // Length
    
    // OID (1.3.6.1.2.1.1.1.0 - sysDescr)
    packet.push_back(0x06); // OBJECT IDENTIFIER
    packet.push_back(0x07); // Length
    packet.insert(packet.end(), {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01});
    
    // NULL value
    packet.push_back(0x05); // NULL
    packet.push_back(0x00); // Length
    
    return packet;
}

// 演示高级统计和监控功能
void demonstrate_advanced_features() {
    std::cout << "\n=== 高级功能演示 ===\n";
    
    // 创建统计系统
    Statistics::TrafficStatistics stats(100);
    
    // 创建性能监控器
    // Monitoring::PerformanceMonitor monitor(1000);
    // monitor.start_monitoring();
    
    // 创建解析器
    auto dhcp_parser = std::make_unique<Parsers::Application::DHCPParser>();
    auto snmp_parser = std::make_unique<Parsers::Application::SNMPParser>();
    
    std::cout << "开始解析和统计数据包...\n";
    
    // 模拟解析多个数据包
    const int packet_count = 1000;
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < packet_count; ++i) {
        // 生成和解析DHCP数据包
        auto dhcp_data = generate_dhcp_packet();
        Core::BufferView dhcp_buffer(dhcp_data.data(), dhcp_data.size());
        
        auto parse_start = std::chrono::high_resolution_clock::now();
        auto result = dhcp_parser->parse(dhcp_buffer);
        auto parse_end = std::chrono::high_resolution_clock::now();
        
        if (result == Parsers::ParseResult::SUCCESS) {
            stats.record_packet("DHCP", dhcp_data.size());
            auto parse_duration = std::chrono::duration_cast<std::chrono::nanoseconds>(parse_end - parse_start);
            stats.record_parse_time("DHCP", parse_duration);
            
            // 记录性能监控数据
            // monitor.record_parse_time("DHCP", parse_duration);
            // monitor.record_throughput("DHCP", 1.0);
        } else {
            stats.record_error("DHCP");
        }
        
        // 生成和解析SNMP数据包
        auto snmp_data = generate_snmp_packet();
        Core::BufferView snmp_buffer(snmp_data.data(), snmp_data.size());
        
        parse_start = std::chrono::high_resolution_clock::now();
        result = snmp_parser->parse(snmp_buffer);
        parse_end = std::chrono::high_resolution_clock::now();
        
        if (result == Parsers::ParseResult::SUCCESS) {
            stats.record_packet("SNMP", snmp_data.size());
            auto parse_duration = std::chrono::duration_cast<std::chrono::nanoseconds>(parse_end - parse_start);
            stats.record_parse_time("SNMP", parse_duration);
            
            // 记录性能监控数据
            // monitor.record_parse_time("SNMP", parse_duration);
            // monitor.record_throughput("SNMP", 1.0);
        } else {
            stats.record_error("SNMP");
        }
        
        // 每100个数据包暂停一下，模拟真实网络流量
        if (i % 100 == 0) {
            std::this_thread::sleep_for(1ms);
        }
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    std::cout << "处理完成！总耗时: " << total_duration.count() << "ms\n\n";
    
    // 显示统计结果
    std::cout << "=== 统计结果 ===\n";
    std::cout << "总协议数: " << stats.total_protocols() << "\n";
    std::cout << "总数据包: " << stats.total_packets() << "\n";
    std::cout << "总字节数: " << stats.total_bytes() << "\n";
    
    // 获取性能指标
    auto perf_metrics = stats.get_performance_metrics();
    std::cout << "每秒数据包数: " << std::fixed << std::setprecision(2) << perf_metrics.packets_per_second << "\n";
    std::cout << "每秒字节数: " << std::fixed << std::setprecision(2) << perf_metrics.bytes_per_second << "\n";
    std::cout << "平均数据包大小: " << std::fixed << std::setprecision(2) << perf_metrics.average_packet_size << " bytes\n";
    std::cout << "错误率: " << std::fixed << std::setprecision(4) << (perf_metrics.error_rate * 100) << "%\n";
    std::cout << "平均解析时间: " << perf_metrics.average_parse_time.count() << " ns\n";
    std::cout << "活跃协议数: " << perf_metrics.active_protocols << "\n\n";
    
    // 显示各协议的详细统计
    std::cout << "=== 协议详细统计 ===\n";
    auto all_stats = stats.get_all_stats();
    for (const auto& [protocol, protocol_stats] : all_stats) {
        std::cout << protocol << ":\n";
        std::cout << "  数据包数: " << protocol_stats.packet_count.value() << "\n";
        std::cout << "  字节数: " << protocol_stats.byte_count.value() << "\n";
        std::cout << "  错误数: " << protocol_stats.error_count.value() << "\n";
        std::cout << "  平均解析时间: " << std::fixed << std::setprecision(3) 
                  << protocol_stats.parse_time.average() << " ms\n";
        std::cout << "  吞吐量方差: " << std::fixed << std::setprecision(3) 
                  << protocol_stats.throughput.variance() << "\n";
        std::cout << "\n";
    }
    
    // 导出统计数据
    std::cout << "=== 导出功能演示 ===\n";
    Statistics::TrafficStatistics::ExportFormat json_format{Statistics::TrafficStatistics::ExportFormat::JSON};
    json_format.include_timestamps = true;
    json_format.include_metadata = true;
    
    std::string json_export = stats.export_stats(json_format);
    std::cout << "JSON导出预览 (前200字符):\n" << json_export.substr(0, 200) << "...\n\n";
    
    // 演示DHCP解析器特定功能
    std::cout << "=== DHCP解析器功能演示 ===\n";
    const auto& dhcp_stats = dhcp_parser->get_statistics();
    std::cout << "DHCP统计:\n";
    std::cout << "  总消息数: " << dhcp_stats.total_messages << "\n";
    std::cout << "  DISCOVER消息: " << dhcp_stats.discover_count << "\n";
    std::cout << "  OFFER消息: " << dhcp_stats.offer_count << "\n";
    std::cout << "  REQUEST消息: " << dhcp_stats.request_count << "\n";
    std::cout << "  ACK消息: " << dhcp_stats.ack_count << "\n";
    std::cout << "  畸形消息: " << dhcp_stats.malformed_count << "\n\n";
    
    // 演示SNMP解析器特定功能
    std::cout << "=== SNMP解析器功能演示 ===\n";
    const auto& snmp_stats = snmp_parser->get_statistics();
    std::cout << "SNMP统计:\n";
    std::cout << "  总消息数: " << snmp_stats.total_messages << "\n";
    std::cout << "  v1消息: " << snmp_stats.v1_messages << "\n";
    std::cout << "  v2c消息: " << snmp_stats.v2c_messages << "\n";
    std::cout << "  v3消息: " << snmp_stats.v3_messages << "\n";
    std::cout << "  GET请求: " << snmp_stats.get_requests << "\n";
    std::cout << "  GET响应: " << snmp_stats.get_responses << "\n";
    std::cout << "  SET请求: " << snmp_stats.set_requests << "\n";
    std::cout << "  TRAP消息: " << snmp_stats.traps << "\n";
    std::cout << "  畸形消息: " << snmp_stats.malformed_messages << "\n";
    
    // 显示community使用情况
    std::cout << "  Community使用情况:\n";
    for (const auto& [community, count] : snmp_stats.community_usage) {
        std::cout << "    " << community << ": " << count << " 次\n";
    }
    
    // monitor.stop_monitoring();
    std::cout << "\n高级功能演示完成！\n";
}

int main() {
    std::cout << "=== 协议解析器扩展功能演示 ===\n\n";
    
    try {
        demonstrate_advanced_features();
        
        std::cout << "\n=== 工具函数演示 ===\n";
        
        // 演示DHCP工具函数
        std::cout << "DHCP工具函数:\n";
        std::cout << "  IP地址转换: " << Parsers::Application::DHCPParser::ip_to_string(0xC0A80001) << "\n";
        std::cout << "  消息类型: " << Parsers::Application::DHCPParser::message_type_to_string(
            Parsers::Application::DHCPOpcode::DISCOVER) << "\n";
        
        // 演示SNMP工具函数
        std::cout << "\nSNMP工具函数:\n";
        std::cout << "  版本转换: " << Parsers::Application::SNMPParser::version_to_string(
            Parsers::Application::SNMPVersion::VERSION_2C) << "\n";
        std::cout << "  PDU类型: " << Parsers::Application::SNMPParser::pdu_type_to_string(
            Parsers::Application::SNMPPDUType::GET_REQUEST) << "\n";
        std::cout << "  错误状态: " << Parsers::Application::SNMPParser::error_status_to_string(
            Parsers::Application::SNMPErrorStatus::NO_ERROR) << "\n";
        
        // 演示OID功能
        std::cout << "\nOID功能演示:\n";
        Parsers::Application::OID system_oid({1, 3, 6, 1, 2, 1, 1});
        Parsers::Application::OID sysDescr_oid("1.3.6.1.2.1.1.1.0");
        
        std::cout << "  系统OID: " << system_oid.to_string() << "\n";
        std::cout << "  sysDescr OID: " << sysDescr_oid.to_string() << "\n";
        std::cout << "  OID有效性: " << (system_oid.is_valid() ? "有效" : "无效") << "\n";
        std::cout << "  前缀关系: " << (system_oid.is_prefix_of(sysDescr_oid) ? "是前缀" : "不是前缀") << "\n";
        
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << "\n";
        return 1;
    }
    
    std::cout << "\n演示程序执行完成！\n";
    return 0;
}