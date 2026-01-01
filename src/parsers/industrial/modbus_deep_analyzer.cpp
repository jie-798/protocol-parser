#include "parsers/industrial/modbus_deep_analyzer.hpp"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace protocol_parser::industrial {

ModbusDeepAnalyzer::ModbusDeepAnalyzer()
    : security_monitoring_enabled_(true)
    , anomaly_detection_enabled_(true)
    , real_time_analysis_(true)
    , max_scan_requests_(100)
    , scan_time_window_(std::chrono::seconds(60))
    , anomaly_threshold_(0.8) {
    
    // 初始化合法功能码集合
    valid_function_codes_ = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10,
        0x16, 0x17, 0x2B, 0x43, 0x14, 0x15, 0x18
    };
    
    // 初始化异常码映射
    exception_codes_ = {
        {0x01, "Illegal Function"},
        {0x02, "Illegal Data Address"},
        {0x03, "Illegal Data Value"},
        {0x04, "Slave Device Failure"},
        {0x05, "Acknowledge"},
        {0x06, "Slave Device Busy"},
        {0x08, "Memory Parity Error"},
        {0x0A, "Gateway Path Unavailable"},
        {0x0B, "Gateway Target Device Failed to Respond"}
    };
    
    // 初始化统计信息
    reset_statistics();
}

bool ModbusDeepAnalyzer::can_parse(const protocol_parser::core::BufferView& buffer) const {
    if (buffer.size() < 8) return false; // 最小MBAP头 + 功能码
    
    // 检查事务ID和协议ID
    uint16_t protocol_id = (buffer[2] << 8) | buffer[3];
    if (protocol_id != 0x0000) return false;
    
    // 检查长度字段
    uint16_t length = (buffer[4] << 8) | buffer[5];
    if (length < 2 || length > 253) return false;
    
    // 检查功能码
    uint8_t function_code = buffer[7];
    return is_valid_function_code(function_code & 0x7F);
}

bool ModbusDeepAnalyzer::parse_modbus_packet(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (!can_parse(buffer)) {
        return false;
    }

    // 手动重置信息结构（不能使用赋值因为包含atomic成员）
    modbus_info.variant = ModbusVariant::TCP;
    modbus_info.transaction_id = 0;
    modbus_info.protocol_id = 0;
    modbus_info.length = 0;
    modbus_info.unit_id = 0;
    modbus_info.mbap_header = ModbusMBAPHeader{};
    modbus_info.function_code = 0;
    modbus_info.is_exception = false;
    modbus_info.exception_code = 0;
    modbus_info.exception_description.clear();
    modbus_info.pdu = ModbusPDU{};
    modbus_info.slave_id = 0;
    modbus_info.crc = 0;
    modbus_info.lrc = 0;
    modbus_info.coils.clear();
    modbus_info.registers.clear();
    modbus_info.coil_values.clear();
    modbus_info.register_values.clear();
    modbus_info.data_payload.clear();
    modbus_info.validation_errors.clear();
    modbus_info.anomalies.clear();
    modbus_info.device_info = ModbusDevice{};
    modbus_info.is_request = true;
    modbus_info.is_broadcast = false;
    modbus_info.start_address = 0;
    modbus_info.starting_address = 0;
    modbus_info.quantity = 0;
    modbus_info.register_count = 0;
    modbus_info.and_mask = 0;
    modbus_info.or_mask = 0;
    modbus_info.read_starting_address = 0;
    modbus_info.read_quantity = 0;
    modbus_info.mei_type = 0;
    modbus_info.device_id_code = 0;
    modbus_info.object_id = 0;
    modbus_info.master_ip.clear();
    modbus_info.slave_ip.clear();
    modbus_info.master_port = 0;
    modbus_info.slave_port = 502;

    // 重置statistics（包含atomic成员）
    modbus_info.statistics.total_requests.store(0);
    modbus_info.statistics.total_responses.store(0);
    modbus_info.statistics.read_requests.store(0);
    modbus_info.statistics.write_requests.store(0);
    modbus_info.statistics.exception_responses.store(0);
    modbus_info.statistics.timeout_errors.store(0);
    modbus_info.statistics.crc_errors.store(0);
    modbus_info.statistics.frame_errors.store(0);
    modbus_info.statistics.bytes_transmitted.store(0);
    modbus_info.statistics.bytes_received.store(0);
    modbus_info.statistics.function_code_counts.clear();
    modbus_info.statistics.slave_message_counts.clear();
    modbus_info.statistics.exception_counts.clear();

    modbus_info.raw_data.clear();
    modbus_info.is_valid = false;
    modbus_info.error_message.clear();
    modbus_info.flow_id = 0;
    modbus_info.parse_timestamp = std::chrono::steady_clock::now();

    // 解析MBAP头
    if (!parse_mbap_header(buffer, modbus_info)) {
        return false;
    }

    // 解析PDU
    size_t pdu_offset = 6; // MBAP头后
    protocol_parser::core::BufferView pdu_buffer(buffer.data() + pdu_offset, modbus_info.length);

    if (!parse_pdu(pdu_buffer, modbus_info)) {
        return false;
    }

    // 执行深度分析
    if (security_monitoring_enabled_) {
        modbus_info.security_analysis = analyze_security(modbus_info);
    }

    if (anomaly_detection_enabled_) {
        analyze_anomalies(modbus_info);
    }

    // 更新统计信息
    update_statistics(modbus_info);

    return true;
}

bool ModbusDeepAnalyzer::parse_mbap_header(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 7) return false;
    
    modbus_info.transaction_id = (buffer[0] << 8) | buffer[1];
    modbus_info.protocol_id = (buffer[2] << 8) | buffer[3];
    modbus_info.length = (buffer[4] << 8) | buffer[5];
    modbus_info.unit_id = buffer[6];
    
    return modbus_info.protocol_id == 0x0000;
}

bool ModbusDeepAnalyzer::parse_pdu(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 1) return false;
    
    modbus_info.function_code = buffer[0];
    modbus_info.is_exception = (modbus_info.function_code & 0x80) != 0;
    
    if (modbus_info.is_exception) {
        return parse_exception_response(buffer, modbus_info);
    }
    
    return parse_function_specific_data(buffer, modbus_info);
}

bool ModbusDeepAnalyzer::parse_exception_response(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 2) return false;
    
    modbus_info.exception_code = buffer[1];
    
    auto it = exception_codes_.find(modbus_info.exception_code);
    if (it != exception_codes_.end()) {
        modbus_info.exception_description = it->second;
    } else {
        modbus_info.exception_description = "Unknown Exception";
    }
    
    return true;
}

bool ModbusDeepAnalyzer::parse_function_specific_data(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    uint8_t func_code = modbus_info.function_code;
    
    switch (func_code) {
        case 0x01: // Read Coils
        case 0x02: // Read Discrete Inputs
            return parse_read_bits_request(buffer, modbus_info);
            
        case 0x03: // Read Holding Registers
        case 0x04: // Read Input Registers
            return parse_read_registers_request(buffer, modbus_info);
            
        case 0x05: // Write Single Coil
            return parse_write_single_coil(buffer, modbus_info);
            
        case 0x06: // Write Single Register
            return parse_write_single_register(buffer, modbus_info);
            
        case 0x0F: // Write Multiple Coils
            return parse_write_multiple_coils(buffer, modbus_info);
            
        case 0x10: // Write Multiple Registers
            return parse_write_multiple_registers(buffer, modbus_info);
            
        case 0x16: // Mask Write Register
            return parse_mask_write_register(buffer, modbus_info);
            
        case 0x17: // Read/Write Multiple Registers
            return parse_read_write_multiple_registers(buffer, modbus_info);
            
        case 0x2B: // Read Device Identification
            return parse_read_device_identification(buffer, modbus_info);
            
        default:
            // 未知功能码，但可能是自定义功能
            modbus_info.data_payload.assign(buffer.data() + 1, buffer.data() + buffer.size());
            return true;
    }
}

bool ModbusDeepAnalyzer::parse_read_bits_request(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 5) return false;
    
    modbus_info.starting_address = (buffer[1] << 8) | buffer[2];
    modbus_info.quantity = (buffer[3] << 8) | buffer[4];
    
    // 验证数量范围
    if (modbus_info.quantity < 1 || modbus_info.quantity > 2000) {
        modbus_info.validation_errors.push_back("Invalid quantity for read bits");
        return false;
    }
    
    return true;
}

bool ModbusDeepAnalyzer::parse_read_registers_request(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 5) return false;
    
    modbus_info.starting_address = (buffer[1] << 8) | buffer[2];
    modbus_info.quantity = (buffer[3] << 8) | buffer[4];
    
    // 验证数量范围
    if (modbus_info.quantity < 1 || modbus_info.quantity > 125) {
        modbus_info.validation_errors.push_back("Invalid quantity for read registers");
        return false;
    }
    
    return true;
}

bool ModbusDeepAnalyzer::parse_write_single_coil(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 5) return false;
    
    modbus_info.starting_address = (buffer[1] << 8) | buffer[2];
    uint16_t value = (buffer[3] << 8) | buffer[4];
    
    // 验证线圈值
    if (value != 0x0000 && value != 0xFF00) {
        modbus_info.validation_errors.push_back("Invalid coil value");
        return false;
    }
    
    modbus_info.coil_values.push_back(value == 0xFF00);
    return true;
}

bool ModbusDeepAnalyzer::parse_write_single_register(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 5) return false;
    
    modbus_info.starting_address = (buffer[1] << 8) | buffer[2];
    uint16_t value = (buffer[3] << 8) | buffer[4];
    
    modbus_info.register_values.push_back(value);
    return true;
}

bool ModbusDeepAnalyzer::parse_write_multiple_coils(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 6) return false;
    
    modbus_info.starting_address = (buffer[1] << 8) | buffer[2];
    modbus_info.quantity = (buffer[3] << 8) | buffer[4];
    uint8_t byte_count = buffer[5];
    
    if (buffer.size() < 6 + byte_count) return false;
    
    // 解析线圈值
    for (size_t i = 0; i < byte_count; ++i) {
        uint8_t byte_val = buffer[6 + i];
        for (int bit = 0; bit < 8 && modbus_info.coil_values.size() < modbus_info.quantity; ++bit) {
            modbus_info.coil_values.push_back((byte_val & (1 << bit)) != 0);
        }
    }
    
    return true;
}

bool ModbusDeepAnalyzer::parse_write_multiple_registers(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 6) return false;
    
    modbus_info.starting_address = (buffer[1] << 8) | buffer[2];
    modbus_info.quantity = (buffer[3] << 8) | buffer[4];
    uint8_t byte_count = buffer[5];
    
    if (buffer.size() < 6 + byte_count || byte_count != modbus_info.quantity * 2) {
        return false;
    }
    
    // 解析寄存器值
    for (size_t i = 0; i < modbus_info.quantity; ++i) {
        uint16_t value = (buffer[6 + i * 2] << 8) | buffer[6 + i * 2 + 1];
        modbus_info.register_values.push_back(value);
    }
    
    return true;
}

bool ModbusDeepAnalyzer::parse_mask_write_register(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 7) return false;
    
    modbus_info.starting_address = (buffer[1] << 8) | buffer[2];
    modbus_info.and_mask = (buffer[3] << 8) | buffer[4];
    modbus_info.or_mask = (buffer[5] << 8) | buffer[6];
    
    return true;
}

bool ModbusDeepAnalyzer::parse_read_write_multiple_registers(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 10) return false;
    
    modbus_info.read_starting_address = (buffer[1] << 8) | buffer[2];
    modbus_info.read_quantity = (buffer[3] << 8) | buffer[4];
    modbus_info.starting_address = (buffer[5] << 8) | buffer[6];
    modbus_info.quantity = (buffer[7] << 8) | buffer[8];
    uint8_t byte_count = buffer[9];
    
    if (buffer.size() < 10 + byte_count) return false;
    
    // 解析写入的寄存器值
    for (size_t i = 0; i < modbus_info.quantity; ++i) {
        uint16_t value = (buffer[10 + i * 2] << 8) | buffer[10 + i * 2 + 1];
        modbus_info.register_values.push_back(value);
    }
    
    return true;
}

bool ModbusDeepAnalyzer::parse_read_device_identification(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 4) return false;
    
    modbus_info.mei_type = buffer[1];
    modbus_info.device_id_code = buffer[2];
    modbus_info.object_id = buffer[3];
    
    return true;
}

ModbusSecurityAnalysis ModbusDeepAnalyzer::analyze_security(const ModbusInfo& info) const {
    ModbusSecurityAnalysis analysis;
    
    // 基础安全检查
    analysis.no_authentication = true; // Modbus本身没有认证
    analysis.no_encryption = true;     // Modbus本身没有加密
    
    // 检测扫描行为
    analysis.scan_detected = detect_scan_attempt(info);
    
    // 检测未授权访问
    if (detect_unauthorized_access(info)) {
        analysis.vulnerabilities.push_back("Potential unauthorized access detected");
    }
    
    // 检测异常功能码使用
    if (!is_valid_function_code(info.function_code & 0x7F)) {
        analysis.vulnerabilities.push_back("Invalid function code used");
    }
    
    // 检测大范围读取
    if (info.quantity > 100) {
        analysis.vulnerabilities.push_back("Large range data access detected");
    }
    
    // 检测写操作安全性
    if (is_write_function(info.function_code)) {
        analysis.vulnerabilities.push_back("Write operation detected - potential security risk");
        
        // 检测关键地址写入
        if (is_critical_address(info.starting_address)) {
            analysis.vulnerabilities.push_back("Write to critical address range");
        }
    }
    
    // 计算安全评分
    analysis.security_score = calculate_security_score(analysis);
    
    return analysis;
}

bool ModbusDeepAnalyzer::detect_scan_attempt(const ModbusInfo& info) const {
    auto now = std::chrono::steady_clock::now();
    
    // 清理过期的扫描记录
    auto cutoff = now - scan_time_window_;
    scan_attempts_.erase(
        std::remove_if(scan_attempts_.begin(), scan_attempts_.end(),
            [cutoff](const ScanAttempt& attempt) {
                return attempt.timestamp < cutoff;
            }),
        scan_attempts_.end()
    );

    // 记录当前请求
    uint8_t unit_id = (info.variant == ModbusVariant::TCP) ? info.mbap_header.unit_id : info.slave_id;
    scan_attempts_.push_back({now, unit_id, static_cast<uint8_t>(info.pdu.function_code), info.start_address});

    // 检测扫描模式
    if (scan_attempts_.size() > 100) {  // 固定阈值
        return true;
    }

    // 检测连续地址扫描
    size_t consecutive_count = 0;
    uint16_t last_address = 0;
    bool first = true;

    for (const auto& attempt : scan_attempts_) {
        if (attempt.unit_id == unit_id && attempt.function_code == static_cast<uint8_t>(info.pdu.function_code)) {
            if (!first && attempt.starting_address == last_address + 1) {
                consecutive_count++;
                if (consecutive_count > 10) {
                    return true;
                }
            } else {
                consecutive_count = 0;
            }
            last_address = attempt.starting_address;
            first = false;
        }
    }

    return false;
}

bool ModbusDeepAnalyzer::detect_unauthorized_access(const ModbusInfo& info) const {
    // 检测访问未授权的单元ID
    uint8_t unit_id = (info.variant == ModbusVariant::TCP) ? info.mbap_header.unit_id : info.slave_id;
    if (unit_id == 0 || unit_id > 247) {
        return true;
    }

    // 检测访问保留地址范围
    if (info.start_address >= 40000 && info.start_address < 40100) {
        return true; // 假设这是保留范围
    }

    // 检测异常大的数据请求
    if (info.quantity > 125) {
        return true;
    }

    return false;
}

void ModbusDeepAnalyzer::analyze_anomalies(ModbusInfo& info) const {
    std::vector<std::string> anomalies;
    
    // 检测时间异常
    auto now = std::chrono::steady_clock::now();
    if (last_packet_time_.time_since_epoch().count() > 0) {
        auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_packet_time_).count();
        
        if (interval < 1) { // 包间隔过短
            anomalies.push_back("Packet interval too short");
        } else if (interval > 30000) { // 包间隔过长
            anomalies.push_back("Packet interval too long");
        }
    }
    last_packet_time_ = now;
    
    // 检测数据异常
    if (info.function_code == 0x03 || info.function_code == 0x04) {
        // 对于读寄存器响应，检测数据模式
        if (info.register_values.size() > 1) {
            bool all_same = std::all_of(info.register_values.begin() + 1, 
                info.register_values.end(),
                [&](uint16_t val) { return val == info.register_values[0]; });
            
            if (all_same) {
                anomalies.push_back("All register values identical");
            }
        }
    }
    
    // 检测事务ID异常
    if (info.transaction_id == 0) {
        anomalies.push_back("Zero transaction ID");
    }
    
    info.anomalies = std::move(anomalies);
}

bool ModbusDeepAnalyzer::is_valid_function_code(uint8_t function_code) const {
    return valid_function_codes_.find(function_code) != valid_function_codes_.end();
}

bool ModbusDeepAnalyzer::is_write_function(uint8_t function_code) const {
    return function_code == 0x05 || function_code == 0x06 || 
           function_code == 0x0F || function_code == 0x10 || 
           function_code == 0x16 || function_code == 0x17;
}

bool ModbusDeepAnalyzer::is_critical_address(uint16_t address) const {
    // 定义关键地址范围 (示例)
    return (address >= 0 && address < 100) ||      // 系统配置
           (address >= 1000 && address < 1100) ||  // 安全参数
           (address >= 9000 && address < 9100);    // 控制命令
}

uint32_t ModbusDeepAnalyzer::calculate_security_score(const ModbusSecurityAnalysis& analysis) const {
    uint32_t score = 100; // 基础分数
    
    // 根据漏洞数量扣分
    score -= analysis.vulnerabilities.size() * 15;
    
    // 扫描检测扣分
    if (analysis.scan_detected) {
        score -= 25;
    }
    
    // 缺乏认证和加密扣分
    if (analysis.no_authentication) {
        score -= 20;
    }
    
    if (analysis.no_encryption) {
        score -= 20;
    }
    
    return std::max(0u, score);
}

void ModbusDeepAnalyzer::update_statistics(const ModbusInfo& info) {
    std::lock_guard<std::mutex> lock(stats_mutex_);

    internal_stats_.total_packets++;
    internal_stats_.function_code_counts[info.function_code]++;
    internal_stats_.unit_id_counts[info.unit_id]++;

    if (info.is_exception) {
        internal_stats_.exception_count++;
        internal_stats_.exception_code_counts[info.exception_code]++;
    }

    if (is_write_function(info.function_code)) {
        internal_stats_.write_operations++;
    } else {
        internal_stats_.read_operations++;
    }

    if (!info.anomalies.empty()) {
        internal_stats_.anomaly_count++;
    }

    if (info.security_analysis.scan_detected) {
        internal_stats_.scan_attempts++;
    }
}

void ModbusDeepAnalyzer::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    internal_stats_ = InternalStats{};

    // 手动重置atomic成员
    global_stats_.total_requests.store(0);
    global_stats_.total_responses.store(0);
    global_stats_.read_requests.store(0);
    global_stats_.write_requests.store(0);
    global_stats_.exception_responses.store(0);
    global_stats_.timeout_errors.store(0);
    global_stats_.crc_errors.store(0);
    global_stats_.frame_errors.store(0);
    global_stats_.bytes_transmitted.store(0);
    global_stats_.bytes_received.store(0);
    global_stats_.function_code_counts.clear();
    global_stats_.slave_message_counts.clear();
    global_stats_.exception_counts.clear();
}

ModbusDeepAnalyzer::InternalStats ModbusDeepAnalyzer::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return internal_stats_;
}

std::string ModbusDeepAnalyzer::generate_security_report(const ModbusInfo& info) const {
    std::stringstream report;
    
    report << "=== Modbus安全分析报告 ===\n";
    report << "时间戳: " << std::chrono::duration_cast<std::chrono::milliseconds>(
        info.parse_timestamp.time_since_epoch()).count() << "ms\n";
    report << "事务ID: 0x" << std::hex << info.transaction_id << std::dec << "\n";
    report << "单元ID: " << static_cast<int>(info.unit_id) << "\n";
    report << "功能码: 0x" << std::hex << static_cast<int>(info.function_code) << std::dec;
    
    if (info.is_exception) {
        report << " (异常响应)\n";
        report << "异常码: 0x" << std::hex << static_cast<int>(info.exception_code) << std::dec 
               << " - " << info.exception_description << "\n";
    } else {
        report << "\n";
    }
    
    report << "\n=== 安全分析 ===\n";
    report << "安全评分: " << info.security_analysis.security_score << "/100\n";
    
    if (!info.security_analysis.vulnerabilities.empty()) {
        report << "发现的安全问题:\n";
        for (const auto& vuln : info.security_analysis.vulnerabilities) {
            report << "  - " << vuln << "\n";
        }
    }
    
    if (info.security_analysis.scan_detected) {
        report << "⚠️  检测到扫描行为\n";
    }
    
    if (!info.anomalies.empty()) {
        report << "\n=== 异常检测 ===\n";
        for (const auto& anomaly : info.anomalies) {
            report << "  - " << anomaly << "\n";
        }
    }
    
    return report.str();
}

} // namespace protocol_parser::industrial