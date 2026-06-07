#include "parsers/industrial/modbus_deep_analyzer.hpp"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <utility>

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
        {static_cast<uint8_t>(0x01), "Illegal Function"},
        {static_cast<uint8_t>(0x02), "Illegal Data Address"},
        {static_cast<uint8_t>(0x03), "Illegal Data Value"},
        {static_cast<uint8_t>(0x04), "Slave Device Failure"},
        {static_cast<uint8_t>(0x05), "Acknowledge"},
        {static_cast<uint8_t>(0x06), "Slave Device Busy"},
        {static_cast<uint8_t>(0x08), "Memory Parity Error"},
        {static_cast<uint8_t>(0x0A), "Gateway Path Unavailable"},
        {static_cast<uint8_t>(0x0B), "Gateway Target Device Failed to Respond"}
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
    if (static_cast<size_t>(length) + 6 > buffer.size()) return false;

    // 检查功能码
    uint8_t function_code = buffer[7];
    return is_valid_function_code(function_code & 0x7F);
}

ModbusVariant ModbusDeepAnalyzer::detect_variant(const protocol_parser::core::BufferView& buffer) const {
    if (can_parse(buffer)) {
        return ModbusVariant::TCP;
    }

    if (buffer.size() >= MODBUS_ASCII_MIN_SIZE &&
        buffer[0] == static_cast<uint8_t>(MODBUS_ASCII_START) &&
        buffer[buffer.size() - 2] == static_cast<uint8_t>(MODBUS_ASCII_END_CR) &&
        buffer[buffer.size() - 1] == static_cast<uint8_t>(MODBUS_ASCII_END_LF)) {
        return ModbusVariant::ASCII;
    }

    return ModbusVariant::RTU;
}

bool ModbusDeepAnalyzer::parse_modbus_tcp(const protocol_parser::core::BufferView& buffer, ModbusInfo& info) {
    return parse_modbus_packet(buffer, info);
}

bool ModbusDeepAnalyzer::parse_modbus_rtu(const protocol_parser::core::BufferView& buffer, ModbusInfo& info) {
    if (buffer.size() < MODBUS_RTU_MIN_SIZE) {
        return false;
    }

    if (crc_validation_enabled_ && !verify_crc(buffer)) {
        info.validation_errors.push_back("Invalid RTU CRC");
        return false;
    }

    info.variant = ModbusVariant::RTU;
    info.slave_id = buffer[0];
    info.unit_id = info.slave_id;
    info.is_broadcast = is_broadcast_address(info.slave_id);
    info.crc = static_cast<uint16_t>(buffer[buffer.size() - 2]) |
               (static_cast<uint16_t>(buffer[buffer.size() - 1]) << 8);

    protocol_parser::core::BufferView pdu_buffer(buffer.data() + 1, buffer.size() - 3);
    if (!parse_pdu(pdu_buffer, info)) {
        return false;
    }

    info.start_address = info.starting_address;
    info.raw_data.assign(buffer.data(), buffer.data() + buffer.size());
    info.is_valid = true;

    if (security_monitoring_enabled_) {
        info.security_analysis = analyze_security(info);
    }

    if (anomaly_detection_enabled_) {
        analyze_anomalies(info);
    }

    update_statistics(info);
    return true;
}

bool ModbusDeepAnalyzer::parse_modbus_ascii(const protocol_parser::core::BufferView& buffer, ModbusInfo& info) {
    if (buffer.size() < MODBUS_ASCII_MIN_SIZE ||
        buffer[0] != static_cast<uint8_t>(MODBUS_ASCII_START) ||
        buffer[buffer.size() - 2] != static_cast<uint8_t>(MODBUS_ASCII_END_CR) ||
        buffer[buffer.size() - 1] != static_cast<uint8_t>(MODBUS_ASCII_END_LF)) {
        return false;
    }

    auto hex_value = [](uint8_t c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };

    const size_t hex_length = buffer.size() - 3;
    if ((hex_length % 2) != 0) {
        return false;
    }

    std::vector<uint8_t> frame;
    frame.reserve(hex_length / 2);
    for (size_t i = 1; i + 1 < buffer.size() - 2; i += 2) {
        int high = hex_value(buffer[i]);
        int low = hex_value(buffer[i + 1]);
        if (high < 0 || low < 0) {
            return false;
        }
        frame.push_back(static_cast<uint8_t>((high << 4) | low));
    }

    if (frame.size() < 3) {
        return false;
    }

    protocol_parser::core::BufferView frame_view(frame.data(), frame.size());
    if (crc_validation_enabled_ && !verify_lrc(frame_view)) {
        info.validation_errors.push_back("Invalid ASCII LRC");
        return false;
    }

    info.variant = ModbusVariant::ASCII;
    info.slave_id = frame[0];
    info.unit_id = info.slave_id;
    info.is_broadcast = is_broadcast_address(info.slave_id);
    info.lrc = frame.back();

    protocol_parser::core::BufferView pdu_buffer(frame.data() + 1, frame.size() - 2);
    if (!parse_pdu(pdu_buffer, info)) {
        return false;
    }

    info.start_address = info.starting_address;
    info.raw_data.assign(buffer.data(), buffer.data() + buffer.size());
    info.is_valid = true;

    if (security_monitoring_enabled_) {
        info.security_analysis = analyze_security(info);
    }

    if (anomaly_detection_enabled_) {
        analyze_anomalies(info);
    }

    update_statistics(info);
    return true;
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
    size_t pdu_offset = MODBUS_TCP_HEADER_SIZE;
    size_t pdu_length = modbus_info.length > 0 ? modbus_info.length - 1 : 0;
    if (pdu_offset + pdu_length > buffer.size()) {
        return false;
    }

    protocol_parser::core::BufferView pdu_buffer(buffer.data() + pdu_offset, pdu_length);

    if (!parse_pdu(pdu_buffer, modbus_info)) {
        return false;
    }
    modbus_info.start_address = modbus_info.starting_address;

    // 执行深度分析
    if (security_monitoring_enabled_) {
        modbus_info.security_analysis = analyze_security(modbus_info);
    }

    if (anomaly_detection_enabled_) {
        analyze_anomalies(modbus_info);
    }

    modbus_info.raw_data.assign(buffer.data(), buffer.data() + buffer.size());
    modbus_info.is_valid = true;

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
    modbus_info.mbap_header.transaction_id = modbus_info.transaction_id;
    modbus_info.mbap_header.protocol_id = modbus_info.protocol_id;
    modbus_info.mbap_header.length = modbus_info.length;
    modbus_info.mbap_header.unit_id = modbus_info.unit_id;
    modbus_info.slave_id = modbus_info.unit_id;
    modbus_info.is_broadcast = is_broadcast_address(modbus_info.unit_id);

    return modbus_info.protocol_id == 0x0000;
}

bool ModbusDeepAnalyzer::parse_pdu(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 1) return false;
    
    modbus_info.function_code = buffer[0];
    modbus_info.is_exception = (modbus_info.function_code & 0x80) != 0;
    modbus_info.pdu.function_code = static_cast<ModbusFunctionCode>(modbus_info.function_code & 0x7F);
    modbus_info.pdu.is_exception = modbus_info.is_exception;
    if (buffer.size() > 1) {
        modbus_info.pdu.data.assign(buffer.data() + 1, buffer.data() + buffer.size());
    }

    if (modbus_info.is_exception) {
        return parse_exception_response(buffer, modbus_info);
    }

    return parse_function_specific_data(buffer, modbus_info);
}

bool ModbusDeepAnalyzer::parse_exception_response(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info) {
    if (buffer.size() < 2) return false;
    
    modbus_info.exception_code = buffer[1];
    modbus_info.pdu.exception_code = static_cast<ModbusExceptionCode>(modbus_info.exception_code);

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
    
    analyze_traffic_patterns(info, analysis);
    analyze_function_codes(info, analysis);
    analyze_access_patterns(info, analysis);
    check_for_attacks(info, analysis);

    // 计算安全评分
    analysis.security_score = calculate_security_score(analysis);
    analysis.is_secure = analysis.security_score >= 80 && analysis.vulnerabilities.empty();
    if (analysis.security_score >= 80) {
        analysis.risk_level = "LOW";
    } else if (analysis.security_score >= 60) {
        analysis.risk_level = "MEDIUM";
    } else if (analysis.security_score >= 40) {
        analysis.risk_level = "HIGH";
    } else {
        analysis.risk_level = "CRITICAL";
    }

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
    int score = 100; // 基础分数

    // 根据漏洞数量扣分
    score -= static_cast<int>(analysis.vulnerabilities.size() * 15);

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

    return static_cast<uint32_t>(std::max(0, score));
}

void ModbusDeepAnalyzer::update_statistics(const ModbusInfo& info) {
    std::lock_guard<std::mutex> lock(stats_mutex_);

    internal_stats_.total_packets++;
    internal_stats_.function_code_counts[info.function_code]++;
    internal_stats_.unit_id_counts[info.unit_id]++;

    global_stats_.function_code_counts[info.function_code]++;
    global_stats_.slave_message_counts[info.unit_id]++;
    global_stats_.bytes_received.fetch_add(info.raw_data.size(), std::memory_order_relaxed);
    global_stats_.last_activity = std::chrono::system_clock::now();

    if (info.is_request) {
        global_stats_.total_requests.fetch_add(1, std::memory_order_relaxed);
    } else {
        global_stats_.total_responses.fetch_add(1, std::memory_order_relaxed);
    }

    if (info.is_exception) {
        internal_stats_.exception_count++;
        internal_stats_.exception_code_counts[info.exception_code]++;
        global_stats_.exception_responses.fetch_add(1, std::memory_order_relaxed);
        global_stats_.exception_counts[info.exception_code]++;
    }

    if (is_write_function(info.function_code)) {
        internal_stats_.write_operations++;
        global_stats_.write_requests.fetch_add(1, std::memory_order_relaxed);
    } else {
        internal_stats_.read_operations++;
        global_stats_.read_requests.fetch_add(1, std::memory_order_relaxed);
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

std::vector<std::string> ModbusDeepAnalyzer::detect_vulnerabilities(const ModbusInfo& info) const {
    std::vector<std::string> vulnerabilities;

    if (info.security_analysis.no_authentication) {
        vulnerabilities.push_back("No authentication support");
    }
    if (info.security_analysis.no_encryption) {
        vulnerabilities.push_back("No encryption support");
    }
    if (detect_unauthorized_access(info)) {
        vulnerabilities.push_back("Potential unauthorized access detected");
    }
    if (is_suspicious_function_code(static_cast<ModbusFunctionCode>(info.function_code & 0x7F))) {
        vulnerabilities.push_back("Suspicious function code used");
    }
    if (is_write_function(info.function_code) && is_critical_address(info.start_address)) {
        vulnerabilities.push_back("Critical address write detected");
    }

    return vulnerabilities;
}

std::vector<std::string> ModbusDeepAnalyzer::detect_anomalies(const ModbusInfo& info) const {
    std::vector<std::string> anomalies = info.anomalies;

    if (is_high_frequency_request(info.unit_id)) {
        anomalies.push_back("High frequency request pattern");
    }
    if (is_unusual_register_access(info.start_address, info.quantity)) {
        anomalies.push_back("Unusual register access range");
    }
    if (info.transaction_id == 0 && info.variant == ModbusVariant::TCP) {
        anomalies.push_back("Zero transaction ID");
    }
    if (info.is_exception) {
        anomalies.push_back("Exception response observed: " + get_exception_name(static_cast<ModbusExceptionCode>(info.exception_code)));
    }

    return anomalies;
}

uint32_t ModbusDeepAnalyzer::calculate_security_score(const ModbusInfo& info) const {
    return calculate_security_score(analyze_security(info));
}

void ModbusDeepAnalyzer::register_device(const ModbusDevice& device) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    known_devices_[device.slave_id] = device;
}

ModbusDevice* ModbusDeepAnalyzer::find_device(uint8_t slave_id) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto it = known_devices_.find(slave_id);
    return it != known_devices_.end() ? &it->second : nullptr;
}

std::vector<ModbusDevice> ModbusDeepAnalyzer::get_known_devices() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    std::vector<ModbusDevice> devices;
    devices.reserve(known_devices_.size());

    for (const auto& [_, device] : known_devices_) {
        devices.push_back(device);
    }

    return devices;
}

void ModbusDeepAnalyzer::update_device_status(uint8_t slave_id, bool online) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    auto& device = known_devices_[slave_id];
    device.slave_id = slave_id;
    device.is_online = online;
    device.last_seen = std::chrono::system_clock::now();
}

bool ModbusDeepAnalyzer::detect_replay_attack(const ModbusInfo& info) const {
    static std::mutex replay_mutex;
    static std::unordered_map<uint64_t, std::chrono::steady_clock::time_point> recent_requests;

    const uint64_t key = (static_cast<uint64_t>(info.unit_id) << 48) |
                         (static_cast<uint64_t>(info.transaction_id) << 16) |
                         info.function_code;
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(replay_mutex);

    for (auto it = recent_requests.begin(); it != recent_requests.end();) {
        if (now - it->second > std::chrono::seconds(60)) {
            it = recent_requests.erase(it);
        } else {
            ++it;
        }
    }

    auto it = recent_requests.find(key);
    if (it != recent_requests.end() && now - it->second < std::chrono::seconds(5)) {
        it->second = now;
        return true;
    }

    recent_requests[key] = now;
    return false;
}

bool ModbusDeepAnalyzer::detect_dos_attempt(const ModbusInfo& info) const {
    return is_high_frequency_request(info.unit_id) ||
           info.quantity > 2000 ||
           info.validation_errors.size() > 3;
}

bool ModbusDeepAnalyzer::verify_crc(const protocol_parser::core::BufferView& buffer) const {
    if (buffer.size() < MODBUS_RTU_MIN_SIZE) {
        return false;
    }

    protocol_parser::core::BufferView payload(buffer.data(), buffer.size() - 2);
    uint16_t calculated = calculate_crc(payload);
    uint16_t received = static_cast<uint16_t>(buffer[buffer.size() - 2]) |
                        (static_cast<uint16_t>(buffer[buffer.size() - 1]) << 8);
    return calculated == received;
}

bool ModbusDeepAnalyzer::verify_lrc(const protocol_parser::core::BufferView& buffer) const {
    if (buffer.size() < 2) {
        return false;
    }

    protocol_parser::core::BufferView payload(buffer.data(), buffer.size() - 1);
    return calculate_lrc(payload) == buffer[buffer.size() - 1];
}

uint16_t ModbusDeepAnalyzer::calculate_crc(const protocol_parser::core::BufferView& buffer) const {
    uint16_t crc = 0xFFFF;

    for (size_t i = 0; i < buffer.size(); ++i) {
        crc ^= buffer[i];
        for (int bit = 0; bit < 8; ++bit) {
            if ((crc & 0x0001) != 0) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }

    return crc;
}

uint8_t ModbusDeepAnalyzer::calculate_lrc(const protocol_parser::core::BufferView& buffer) const {
    uint8_t sum = 0;
    for (size_t i = 0; i < buffer.size(); ++i) {
        sum = static_cast<uint8_t>(sum + buffer[i]);
    }
    return static_cast<uint8_t>(-sum);
}

void ModbusDeepAnalyzer::analyze_traffic_patterns(const ModbusInfo& info, ModbusSecurityAnalysis& analysis) const {
    if (info.is_broadcast) {
        analysis.broadcast_detected = true;
        analysis.warnings.push_back("Broadcast request detected");
    }
    if (is_high_frequency_request(info.unit_id)) {
        analysis.abnormal_traffic_pattern = true;
        analysis.vulnerabilities.push_back("High frequency Modbus traffic detected");
    }
}

void ModbusDeepAnalyzer::analyze_function_codes(const ModbusInfo& info, ModbusSecurityAnalysis& analysis) const {
    auto function_code = static_cast<ModbusFunctionCode>(info.function_code & 0x7F);
    if (is_suspicious_function_code(function_code)) {
        analysis.suspicious_function_codes = true;
        analysis.vulnerabilities.push_back("Suspicious Modbus function code");
    }
    if (is_write_function(info.function_code)) {
        analysis.warnings.push_back("Write function used");
    }
}

void ModbusDeepAnalyzer::analyze_access_patterns(const ModbusInfo& info, ModbusSecurityAnalysis& analysis) const {
    if (is_unusual_register_access(info.start_address, info.quantity)) {
        analysis.abnormal_traffic_pattern = true;
        analysis.vulnerabilities.push_back("Unusual register access pattern");
    }
    if (detect_unauthorized_access(info)) {
        analysis.unauthorized_access = true;
        analysis.vulnerabilities.push_back("Unauthorized access pattern");
    }
}

void ModbusDeepAnalyzer::check_for_attacks(const ModbusInfo& info, ModbusSecurityAnalysis& analysis) const {
    if (detect_replay_attack(info)) {
        analysis.potential_replay_attack = true;
        analysis.vulnerabilities.push_back("Potential replay attack");
    }
    if (detect_dos_attempt(info)) {
        analysis.potential_dos_attack = true;
        analysis.vulnerabilities.push_back("Potential denial-of-service pattern");
    }
}

bool ModbusDeepAnalyzer::is_suspicious_function_code(ModbusFunctionCode fc) const {
    uint8_t function_code = static_cast<uint8_t>(fc);
    return !is_valid_function_code(function_code) ||
           function_code == static_cast<uint8_t>(ModbusFunctionCode::DIAGNOSTICS) ||
           function_code == static_cast<uint8_t>(ModbusFunctionCode::ENCAPSULATED_INTERFACE_TRANSPORT);
}

bool ModbusDeepAnalyzer::is_high_frequency_request(uint8_t slave_id) const {
    auto now = std::chrono::steady_clock::now();
    size_t count = 0;

    for (const auto& attempt : scan_attempts_) {
        if (attempt.unit_id == slave_id && now - attempt.timestamp <= std::chrono::seconds(1)) {
            ++count;
        }
    }

    return count > MAX_REQUESTS_PER_SECOND;
}

bool ModbusDeepAnalyzer::is_unusual_register_access(uint16_t start_addr, uint16_t count) const {
    if (count > MAX_REGISTER_COUNT) {
        return true;
    }

    uint32_t end_addr = static_cast<uint32_t>(start_addr) + count;
    return end_addr > 10000 || is_critical_address(start_addr);
}

std::string ModbusDeepAnalyzer::get_exception_name(ModbusExceptionCode code) const {
    uint8_t raw_code = static_cast<uint8_t>(code);
    auto it = exception_codes_.find(raw_code);
    return it != exception_codes_.end() ? it->second : "Unknown Exception";
}

std::string ModbusDeepAnalyzer::get_variant_name(ModbusVariant variant) const {
    switch (variant) {
        case ModbusVariant::RTU: return "RTU";
        case ModbusVariant::ASCII: return "ASCII";
        case ModbusVariant::TCP: return "TCP";
        case ModbusVariant::UDP: return "UDP";
    }

    return "Unknown";
}

std::string ModbusDeepAnalyzer::generate_security_report() const {
    auto stats = get_statistics();
    std::stringstream report;

    report << "=== Modbus安全统计报告 ===\n";
    report << "总包数: " << stats.total_packets << "\n";
    report << "读操作: " << stats.read_operations << "\n";
    report << "写操作: " << stats.write_operations << "\n";
    report << "异常响应: " << stats.exception_count << "\n";
    report << "异常事件: " << stats.anomaly_count << "\n";
    report << "扫描尝试: " << stats.scan_attempts << "\n";

    return report.str();
}

std::string ModbusDeepAnalyzer::generate_device_report() const {
    auto devices = get_known_devices();
    std::stringstream report;

    report << "=== Modbus设备报告 ===\n";
    report << "设备数量: " << devices.size() << "\n";
    for (const auto& device : devices) {
        report << "Slave ID: " << static_cast<int>(device.slave_id)
               << ", 状态: " << (device.is_online ? "online" : "offline")
               << ", 消息数: " << device.message_count
               << ", 错误率: " << std::fixed << std::setprecision(2) << device.get_error_rate() << "\n";
    }

    return report.str();
}

} // namespace protocol_parser::industrial