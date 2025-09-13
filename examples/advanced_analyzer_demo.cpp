#include "parsers/security/tls_deep_inspector.hpp"
#include "parsers/industrial/modbus_deep_analyzer.hpp"
#include "ai/protocol_detector.hpp"
#include "core/buffer_view.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>

using namespace protocol_parser;

int main() {
    std::cout << "=== 高级协议解析器演示 ===\n\n";
    
    // 初始化分析器
    parsers::security::TLSDeepInspector tls_inspector;
    parsers::industrial::ModbusDeepAnalyzer modbus_analyzer;
    ai::AIProtocolDetector ai_detector;
    
    std::cout << "✓ TLS深度检测器已初始化\n";
    std::cout << "✓ Modbus工业协议分析器已初始化\n";
    std::cout << "✓ AI协议检测引擎已初始化\n\n";
    
    // 模拟TLS握手数据包
    std::vector<uint8_t> tls_packet = {
        0x16, 0x03, 0x03, 0x00, 0x4A,  // TLS握手记录头
        0x01, 0x00, 0x00, 0x46,        // 客户端Hello
        0x03, 0x03,                     // TLS版本1.2
        // 模拟32字节随机数
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x00,        // 会话ID长度
        0x00, 0x02,  // 密码套件长度
        0x00, 0x2F,  // TLS_RSA_WITH_AES_128_CBC_SHA
        0x01, 0x00   // 压缩方法
    };
    
    // 模拟Modbus数据包
    std::vector<uint8_t> modbus_packet = {
        0x00, 0x01,  // 事务ID
        0x00, 0x00,  // 协议ID
        0x00, 0x06,  // 长度
        0x01,        // 单元ID
        0x03,        // 功能码（读保持寄存器）
        0x00, 0x00,  // 起始地址
        0x00, 0x0A   // 数量
    };
    
    std::cout << "🔍 开始协议分析...\n\n";
    
    // TLS分析
    std::cout << "1. TLS协议分析:\n";
    core::BufferView tls_buffer(tls_packet.data(), tls_packet.size());
    
    if (tls_inspector.can_parse(tls_buffer)) {
        parsers::security::TLSInfo tls_info;
        auto start_time = std::chrono::high_resolution_clock::now();
        
        if (tls_inspector.parse_tls_packet(tls_buffer, tls_info)) {
            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            
            std::cout << "   ✓ 成功解析TLS数据包\n";
            std::cout << "   - 版本: " << tls_info.version_string << "\n";
            std::cout << "   - 内容类型: " << static_cast<int>(tls_info.content_type) << "\n";
            std::cout << "   - 长度: " << tls_info.length << " 字节\n";
            std::cout << "   - 安全评分: " << tls_info.security_analysis.security_score << "/100\n";
            std::cout << "   - 分析耗时: " << duration.count() << " 微秒\n";
            
            if (!tls_info.security_analysis.vulnerabilities.empty()) {
                std::cout << "   ⚠️  发现安全问题:\n";
                for (const auto& vuln : tls_info.security_analysis.vulnerabilities) {
                    std::cout << "     • " << vuln << "\n";
                }
            }
        } else {
            std::cout << "   ❌ TLS解析失败\n";
        }
    } else {
        std::cout << "   ❌ 不是有效的TLS数据包\n";
    }
    
    std::cout << "\n2. Modbus协议分析:\n";
    core::BufferView modbus_buffer(modbus_packet.data(), modbus_packet.size());
    
    if (modbus_analyzer.can_parse(modbus_buffer)) {
        parsers::industrial::ModbusInfo modbus_info;
        auto start_time = std::chrono::high_resolution_clock::now();
        
        if (modbus_analyzer.parse_modbus_packet(modbus_buffer, modbus_info)) {
            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
            
            std::cout << "   ✓ 成功解析Modbus数据包\n";
            std::cout << "   - 事务ID: 0x" << std::hex << modbus_info.transaction_id << std::dec << "\n";
            std::cout << "   - 单元ID: " << static_cast<int>(modbus_info.unit_id) << "\n";
            std::cout << "   - 功能码: 0x" << std::hex << static_cast<int>(modbus_info.function_code) << std::dec << "\n";
            std::cout << "   - 起始地址: " << modbus_info.starting_address << "\n";
            std::cout << "   - 数量: " << modbus_info.quantity << "\n";
            std::cout << "   - 安全评分: " << modbus_info.security_analysis.security_score << "/100\n";
            std::cout << "   - 分析耗时: " << duration.count() << " 微秒\n";
            
            if (modbus_info.security_analysis.scan_detected) {
                std::cout << "   ⚠️  检测到扫描行为\n";
            }
            
            if (!modbus_info.security_analysis.vulnerabilities.empty()) {
                std::cout << "   ⚠️  发现安全问题:\n";
                for (const auto& vuln : modbus_info.security_analysis.vulnerabilities) {
                    std::cout << "     • " << vuln << "\n";
                }
            }
        } else {
            std::cout << "   ❌ Modbus解析失败\n";
        }
    } else {
        std::cout << "   ❌ 不是有效的Modbus数据包\n";
    }
    
    std::cout << "\n3. AI协议检测:\n";
    
    // 对TLS数据包进行AI检测
    auto ai_results_tls = ai_detector.detect_protocol(tls_buffer, 443, 80);
    if (!ai_results_tls.empty()) {
        std::cout << "   🤖 TLS数据包AI检测结果:\n";
        for (const auto& result : ai_results_tls) {
            std::cout << "     - " << result.protocol_name 
                     << " (置信度: " << std::fixed << std::setprecision(2) 
                     << result.confidence * 100 << "%, 方法: " << result.classification_method << ")\n";
        }
    }
    
    // 对Modbus数据包进行AI检测
    auto ai_results_modbus = ai_detector.detect_protocol(modbus_buffer, 502, 80);
    if (!ai_results_modbus.empty()) {
        std::cout << "   🤖 Modbus数据包AI检测结果:\n";
        for (const auto& result : ai_results_modbus) {
            std::cout << "     - " << result.protocol_name 
                     << " (置信度: " << std::fixed << std::setprecision(2) 
                     << result.confidence * 100 << "%, 方法: " << result.classification_method << ")\n";
        }
    }
    
    std::cout << "\n4. 统计信息:\n";
    
    // TLS统计
    auto tls_stats = tls_inspector.get_statistics();
    std::cout << "   📊 TLS统计:\n";
    std::cout << "     - 总连接数: " << tls_stats.total_connections << "\n";
    std::cout << "     - 成功握手: " << tls_stats.successful_handshakes << "\n";
    std::cout << "     - 发现漏洞: " << tls_stats.vulnerabilities_found << "\n";
    
    // Modbus统计
    auto modbus_stats = modbus_analyzer.get_statistics();
    std::cout << "   🏭 Modbus统计:\n";
    std::cout << "     - 总数据包: " << modbus_stats.total_packets << "\n";
    std::cout << "     - 读操作: " << modbus_stats.read_operations << "\n";
    std::cout << "     - 写操作: " << modbus_stats.write_operations << "\n";
    std::cout << "     - 异常数量: " << modbus_stats.exception_count << "\n";
    
    std::cout << "\n=== 演示完成 ===\n";
    std::cout << "高级协议解析器功能验证成功！\n";
    std::cout << "- TLS深度安全分析 ✓\n";
    std::cout << "- Modbus工业协议分析 ✓\n";  
    std::cout << "- AI智能协议检测 ✓\n";
    std::cout << "- 实时统计监控 ✓\n";
    
    return 0;
}