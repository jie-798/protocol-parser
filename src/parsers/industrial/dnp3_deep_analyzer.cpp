#include "parsers/industrial/dnp3_deep_analyzer.hpp"
#include "parsers/industrial/dnp3_deep_analyzer.hpp"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace protocol_parser::parsers::industrial {

// DNP3 CRC查找表 - 完整版
const std::array<uint16_t, 256> DNP3DeepAnalyzer::crc_table_ = {{
    0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
    0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
    0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
    0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
    0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
    0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
    0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
    0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
    0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
    0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
    0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
    0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
    0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
    0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
    0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
    0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
    0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
    0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
    0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
    0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
    0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
    0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
    0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
    0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
    0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
    0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
    0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
    0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
    0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
    0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
    0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
    0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235
}};

DNP3DeepAnalyzer::DNP3DeepAnalyzer()
    : security_monitoring_enabled_(true)
    , anomaly_detection_enabled_(true)
    , deep_inspection_enabled_(true)
    , authentication_required_(false)
    , anomaly_threshold_(0.8) {
    
    initialize_object_definitions();
    initialize_function_codes();
    initialize_security_settings();
    
    reset_statistics();
}

bool DNP3DeepAnalyzer::can_parse(const protocol_parser::core::BufferView& buffer) const {
    if (buffer.size() < 10) return false; // 最小DNP3帧大小
    
    // 检查起始字节 0x05 0x64
    if (buffer[0] != 0x05 || buffer[1] != 0x64) return false;
    
    // 检查长度字段
    uint8_t length = buffer[2];
    if (length < 5 || length > 255) return false;
    
    // 检查控制字段的合理性
    uint8_t control = buffer[3];
    uint8_t func_code = control & 0x0F;
    if (func_code > 15) return false;
    
    return true;
}

bool DNP3DeepAnalyzer::parse_datalink_header(const protocol_parser::core::BufferView& buffer, DNP3DataLinkInfo& dl_info) {
    if (buffer.size() < 10) return false;
    
    dl_info.start_byte_1 = buffer[0];
    dl_info.start_byte_2 = buffer[1];
    dl_info.length = buffer[2];
    dl_info.control = buffer[3];
    dl_info.destination = (buffer[4] << 8) | buffer[5];
    dl_info.source = (buffer[6] << 8) | buffer[7];
    dl_info.crc = (buffer[8] << 8) | buffer[9];
    
    // 解析控制字段
    return parse_datalink_control(dl_info.control, dl_info);
}

bool DNP3DeepAnalyzer::parse_datalink_control(uint8_t control, DNP3DataLinkInfo& dl_info) {
    dl_info.direction = (control & 0x80) != 0;
    dl_info.primary = (control & 0x40) != 0;
    dl_info.frame_count_bit = (control & 0x20) != 0;
    dl_info.data_flow_control = (control & 0x10) != 0;
    dl_info.function_code = control & 0x0F;
    
    return true;
}

bool DNP3DeepAnalyzer::validate_datalink_crc(const protocol_parser::core::BufferView& buffer) const {
    if (buffer.size() < 10) return false;
    
    // 计算前8字节的CRC
    uint16_t calculated_crc = calculate_crc(protocol_parser::core::BufferView(buffer.data(), 8));
    uint16_t received_crc = (buffer[8] << 8) | buffer[9];
    
    return calculated_crc == received_crc;
}

bool DNP3DeepAnalyzer::parse_transport_header(const protocol_parser::core::BufferView& buffer, DNP3TransportInfo& transport_info) {
    if (buffer.size() < 1) return false;
    
    uint8_t transport_control = buffer[0];
    transport_info.fin = (transport_control & 0x80) != 0;
    transport_info.fir = (transport_control & 0x40) != 0;
    transport_info.sequence = transport_control & 0x3F;
    
    // 拷贝传输数据
    if (buffer.size() > 1) {
        transport_info.data.assign(buffer.data() + 1, buffer.data() + buffer.size());
    }
    
    return true;
}

bool DNP3DeepAnalyzer::parse_application_header(const protocol_parser::core::BufferView& buffer, DNP3ApplicationInfo& app_info) {
    if (buffer.size() < 2) return false;
    
    app_info.application_control = buffer[0];
    app_info.function_code = buffer[1];
    
    // 解析应用控制字段
    app_info.fir = (app_info.application_control & 0x80) != 0;
    app_info.fin = (app_info.application_control & 0x40) != 0;
    app_info.con = (app_info.application_control & 0x20) != 0;
    app_info.uns = (app_info.application_control & 0x10) != 0;
    app_info.sequence = app_info.application_control & 0x0F;
    
    // 某些功能码包含内部指示
    if (buffer.size() >= 4 && (app_info.function_code == 0x81 || app_info.function_code == 0x82)) {
        app_info.internal_indications = (buffer[2] << 8) | buffer[3];
    }
    
    // 解析对象和变化
    if (buffer.size() > (app_info.internal_indications != 0 ? 4 : 2)) {
        size_t object_offset = app_info.internal_indications != 0 ? 4 : 2;
        protocol_parser::core::BufferView object_buffer(
            buffer.data() + object_offset,
            buffer.size() - object_offset);
        
        parse_application_objects(object_buffer, app_info);
    }
    
    return true;
}

bool DNP3DeepAnalyzer::parse_application_objects(const protocol_parser::core::BufferView& buffer, DNP3ApplicationInfo& app_info) {
    size_t offset = 0;
    
    while (offset + 3 < buffer.size()) {
        DNP3Object object;
        
        if (!parse_object_header(buffer, offset, object)) {
            break;
        }
        
        if (!parse_object_data(buffer, offset, object)) {
            break;
        }
        
        app_info.objects.push_back(object);
    }
    
    return !app_info.objects.empty();
}

bool DNP3DeepAnalyzer::parse_object_header(const protocol_parser::core::BufferView& buffer, size_t& offset, DNP3Object& object) {
    if (offset + 3 > buffer.size()) return false;
    
    object.group = buffer[offset];
    object.variation = buffer[offset + 1];
    object.qualifier = buffer[offset + 2];
    offset += 3;
    
    // 根据限定符解析范围
    uint8_t range_type = object.qualifier & 0x70;
    
    if (range_type == 0x00) { // 起始-停止索引
        if (offset + 4 > buffer.size()) return false;
        object.range_start = (buffer[offset] << 8) | buffer[offset + 1];
        object.range_stop = (buffer[offset + 2] << 8) | buffer[offset + 3];
        offset += 4;
    } else if (range_type == 0x10) { // 起始索引+数量
        if (offset + 4 > buffer.size()) return false;
        object.range_start = (buffer[offset] << 8) | buffer[offset + 1];
        uint16_t quantity = (buffer[offset + 2] << 8) | buffer[offset + 3];
        object.range_stop = object.range_start + quantity - 1;
        offset += 4;
    }
    
    return true;
}

bool DNP3DeepAnalyzer::parse_object_data(const protocol_parser::core::BufferView& buffer, size_t& offset, DNP3Object& object) {
    // 根据对象组和变化确定数据大小
    size_t data_size = get_object_data_size(object.group, object.variation);
    size_t item_count = object.range_stop - object.range_start + 1;
    size_t total_data_size = data_size * item_count;
    
    if (offset + total_data_size > buffer.size()) {
        // 数据不完整，但不是致命错误
        total_data_size = buffer.size() - offset;
    }
    
    if (total_data_size > 0) {
        object.object_data.assign(buffer.data() + offset, buffer.data() + offset + total_data_size);
        offset += total_data_size;
    }
    
    return true;
}

size_t DNP3DeepAnalyzer::get_object_data_size(uint8_t group, uint8_t variation) const {
    // 常见DNP3对象数据大小映射
    if (group == 1) { // Binary Input
        if (variation == 1) return 0; // Packed format
        if (variation == 2) return 1; // With flags
    } else if (group == 10) { // Binary Output
        if (variation == 1) return 0; // Packed format
        if (variation == 2) return 1; // With flags
    } else if (group == 20) { // Binary Counter
        if (variation == 1) return 5; // 32-bit with flag
        if (variation == 2) return 3; // 16-bit with flag
    } else if (group == 30) { // Analog Input
        if (variation == 1) return 5; // 32-bit with flag
        if (variation == 2) return 3; // 16-bit with flag
        if (variation == 3) return 4; // 32-bit without flag
    } else if (group == 40) { // Analog Output Status
        if (variation == 1) return 5; // 32-bit with flag
        if (variation == 2) return 3; // 16-bit with flag
    }
    
    return 1; // 默认数据大小
}

uint16_t DNP3DeepAnalyzer::calculate_crc(const protocol_parser::core::BufferView& buffer) const {
    uint16_t crc = 0x0000;
    
    for (size_t i = 0; i < buffer.size(); ++i) {
        uint8_t index = (crc ^ buffer[i]) & 0xFF;
        crc = (crc >> 8) ^ crc_table_[index];
    }
    
    return crc;
}

DNP3SecurityAnalysis DNP3DeepAnalyzer::analyze_security(const DNP3Info& info) const {
    DNP3SecurityAnalysis analysis;
    
    // 基础安全检查
    analysis.authentication_enabled = false; // DNP3本身不支持认证
    analysis.secure_authentication = false;
    
    // 检测广播使用
    analysis.broadcast_detected = (info.datalink_info.destination == 0xFFFF);
    
    // 检测时间同步
    if (info.application_info.function_code == 0x07) { // Time and Date
        analysis.time_sync_detected = true;
    }
    
    // 检测配置更改
    if (is_configuration_function(info.application_info.function_code)) {
        analysis.configuration_change = true;
        analysis.operational_risks.push_back("Configuration change detected");
    }
    
    // 检测关键功能执行
    if (is_critical_function(info.application_info.function_code)) {
        analysis.critical_function_executed = true;
        analysis.operational_risks.push_back("Critical function executed");
    }
    
    // 检测攻击模式
    if (detect_broadcast_abuse(info)) {
        analysis.security_issues.push_back("Broadcast abuse detected");
    }
    
    if (detect_replay_attack(info)) {
        analysis.replay_attack_possible = true;
        analysis.security_issues.push_back("Potential replay attack");
    }
    
    if (detect_timing_attacks(info)) {
        analysis.security_issues.push_back("Timing attack patterns detected");
    }
    
    // 计算安全评分
    analysis.security_score = calculate_security_score(analysis);
    analysis.risk_level = determine_risk_level(analysis.security_score);
    
    return analysis;
}

bool DNP3DeepAnalyzer::detect_attack_patterns(const DNP3Info& info) const {
    // 检测DoS攻击模式
    if (detect_dos_attack(info)) {
        return true;
    }
    
    // 检测扫描行为
    if (detect_scan_attempt(info)) {
        return true;
    }
    
    // 检测异常序列号
    if (detect_sequence_anomalies(info)) {
        return true;
    }
    
    return false;
}

bool DNP3DeepAnalyzer::detect_anomalies(const DNP3Info& info) const {
    double anomaly_score = calculate_packet_anomaly_score(info);
    return anomaly_score > anomaly_threshold_;
}

void DNP3DeepAnalyzer::analyze_anomalies(DNP3Info& info) const {
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
    // 使用const_cast更新mutable成员
    const_cast<DNP3DeepAnalyzer*>(this)->last_packet_time_ = now;
    
    // 检测数据异常
    if (info.datalink_info.length > 250) {
        anomalies.push_back("Unusually large packet size");
    }
    
    // 检测地址异常
    if (info.datalink_info.source == 0 || info.datalink_info.destination == 0) {
        anomalies.push_back("Invalid address detected");
    }
    
    // 检测功能码异常
    if (info.application_info.function_code > 0x82 && info.application_info.function_code != 0x83) {
        anomalies.push_back("Unknown function code");
    }
    
    info.anomalies = std::move(anomalies);
}

void DNP3DeepAnalyzer::initialize_object_definitions() {
    // 初始化常见DNP3对象定义
    object_definitions_["1:1"] = "Binary Input - Packed Format";
    object_definitions_["1:2"] = "Binary Input - With Flags";
    object_definitions_["2:1"] = "Binary Input Change - Without Time";
    object_definitions_["2:2"] = "Binary Input Change - With Absolute Time";
    object_definitions_["10:1"] = "Binary Output - Packed Format";
    object_definitions_["10:2"] = "Binary Output Status - With Flags";
    object_definitions_["12:1"] = "Binary Command - CROB";
    object_definitions_["20:1"] = "Binary Counter - 32-bit With Flag";
    object_definitions_["20:2"] = "Binary Counter - 16-bit With Flag";
    object_definitions_["30:1"] = "Analog Input - 32-bit With Flag";
    object_definitions_["30:2"] = "Analog Input - 16-bit With Flag";
    object_definitions_["30:3"] = "Analog Input - 32-bit Without Flag";
    object_definitions_["40:1"] = "Analog Output Status - 32-bit With Flag";
    object_definitions_["40:2"] = "Analog Output Status - 16-bit With Flag";
    object_definitions_["41:1"] = "Analog Output - 32-bit";
    object_definitions_["41:2"] = "Analog Output - 16-bit";
    object_definitions_["50:1"] = "Time and Date";
    object_definitions_["50:2"] = "Time and Date with Interval";
    object_definitions_["60:1"] = "Class 0 Data";
    object_definitions_["60:2"] = "Class 1 Data";
    object_definitions_["60:3"] = "Class 2 Data";
    object_definitions_["60:4"] = "Class 3 Data";
}

void DNP3DeepAnalyzer::initialize_function_codes() {
    // 数据链路层功能码
    function_code_names_[0] = "Reset Link States";
    function_code_names_[1] = "Reset User Process";
    function_code_names_[2] = "Test Link States";
    function_code_names_[3] = "User Data";
    function_code_names_[4] = "Request Link Status";
    function_code_names_[9] = "Request User Data";
    function_code_names_[11] = "Link Status";
    function_code_names_[14] = "Not Supported";
    function_code_names_[15] = "Not Used";
    
    // 应用层功能码
    application_function_names_[0x01] = "Read";
    application_function_names_[0x02] = "Write";
    application_function_names_[0x03] = "Select";
    application_function_names_[0x04] = "Operate";
    application_function_names_[0x05] = "Direct Operate";
    application_function_names_[0x06] = "Direct Operate No Response";
    application_function_names_[0x07] = "Immediate Freeze";
    application_function_names_[0x0D] = "Cold Restart";
    application_function_names_[0x0E] = "Warm Restart";
    application_function_names_[0x13] = "Save Configuration";
    application_function_names_[0x18] = "Record Current Time";
    application_function_names_[0x81] = "Response";
    application_function_names_[0x82] = "Unsolicited Response";
    application_function_names_[0x83] = "Authenticate Response";
}

void DNP3DeepAnalyzer::initialize_security_settings() {
    // 设置授权的主站和从站地址
    authorized_masters_.insert(1);
    authorized_masters_.insert(2);
    
    authorized_outstations_.insert(10);
    authorized_outstations_.insert(11);
    authorized_outstations_.insert(12);
    
    // 设置监控地址
    monitored_addresses_.insert(10);
    monitored_addresses_.insert(11);
}

bool DNP3DeepAnalyzer::is_critical_function(uint8_t function_code) const {
    return function_code == 0x0D || // Cold Restart
           function_code == 0x0E || // Warm Restart
           function_code == 0x04 || // Operate
           function_code == 0x05 || // Direct Operate
           function_code == 0x02;   // Write
}

bool DNP3DeepAnalyzer::is_configuration_function(uint8_t function_code) const {
    return function_code == 0x13 || // Save Configuration
           function_code == 0x0F || // Initialize Data
           function_code == 0x10 || // Initialize Application
           function_code == 0x16;   // Assign Class
}

bool DNP3DeepAnalyzer::detect_broadcast_abuse(const DNP3Info& info) const {
    // 检测广播地址的异常使用
    if (info.datalink_info.destination == 0xFFFF) {
        // 广播消息应该只用于特定功能
        if (info.application_info.function_code == 0x18) { // Record Current Time
            return false; // 正常的时间同步广播
        }
        
        // 其他广播使用可能是攻击
        return true;
    }
    
    return false;
}

bool DNP3DeepAnalyzer::detect_timing_attacks(const DNP3Info& info) const {
    auto now = std::chrono::steady_clock::now();
    
    // 检测高频请求
    if (last_packet_time_.time_since_epoch().count() > 0) {
        auto interval = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_packet_time_).count();
        
        if (interval < 10) { // 间隔小于10ms
            return true;
        }
    }
    
    // 使用const_cast更新mutable成员
    const_cast<DNP3DeepAnalyzer*>(this)->last_packet_time_ = now;
    return false;
}

bool DNP3DeepAnalyzer::detect_replay_attack(const DNP3Info& info) const {
    // 检测相同的应用层序列号
    uint32_t seq_key = (static_cast<uint32_t>(info.datalink_info.source) << 16) | info.application_info.sequence;
    
    auto now = std::chrono::steady_clock::now();
    static std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> sequence_map;
    
    auto it = sequence_map.find(seq_key);
    if (it != sequence_map.end()) {
        auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
        if (time_diff < 60) { // 1分钟内重复序列号
            return true;
        }
    }
    
    sequence_map[seq_key] = now;
    return false;
}

bool DNP3DeepAnalyzer::detect_dos_attack(const DNP3Info& info) const {
    // 检测大量请求或异常数据包
    if (info.datalink_info.length > 200) {
        return true; // 异常大的数据包
    }
    
    return false;
}

bool DNP3DeepAnalyzer::detect_scan_attempt(const DNP3Info& info) const {
    // 检测扫描行为（连续访问不同地址）
    static std::unordered_map<uint16_t, std::set<uint16_t>> source_destinations;
    
    auto& destinations = source_destinations[info.datalink_info.source];
    destinations.insert(info.datalink_info.destination);
    
    // 如果一个源地址访问超过10个不同目标，可能是扫描
    return destinations.size() > 10;
}

bool DNP3DeepAnalyzer::detect_sequence_anomalies(const DNP3Info& info) const {
    // 检测序列号异常
    if (info.transport_info.sequence > 63) {
        return true; // DNP3序列号范围是0-63
    }
    
    return false;
}

double DNP3DeepAnalyzer::calculate_packet_anomaly_score(const DNP3Info& info) const {
    double score = 0.0;
    
    // 大小异常
    if (info.datalink_info.length > 250) {
        score += 0.3;
    }
    
    // 功能码异常
    if (info.application_info.function_code > 0x82 && info.application_info.function_code != 0x83) {
        score += 0.4;
    }
    
    // 地址异常
    if (info.datalink_info.source == 0 || info.datalink_info.destination == 0) {
        score += 0.2;
    }
    
    // CRC错误
    if (!info.crc_valid) {
        score += 0.5;
    }
    
    return std::min(score, 1.0);
}

uint32_t DNP3DeepAnalyzer::calculate_security_score(const DNP3SecurityAnalysis& analysis) const {
    uint32_t score = 100;
    
    // 根据安全问题扣分
    score -= analysis.security_issues.size() * 15;
    score -= analysis.operational_risks.size() * 10;
    
    // 广播检测扣分
    if (analysis.broadcast_detected) {
        score -= 5;
    }
    
    // 关键功能执行扣分
    if (analysis.critical_function_executed) {
        score -= 20;
    }
    
    // 重放攻击可能性扣分
    if (analysis.replay_attack_possible) {
        score -= 25;
    }
    
    return std::max(0u, score);
}

std::string DNP3DeepAnalyzer::determine_risk_level(uint32_t security_score) const {
    if (security_score >= 80) return "LOW";
    if (security_score >= 60) return "MEDIUM";
    if (security_score >= 40) return "HIGH";
    return "CRITICAL";
}

void DNP3DeepAnalyzer::update_statistics(const DNP3Info& info) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.total_frames++;
    
    if (info.valid_frame) {
        stats_.valid_frames++;
    } else {
        stats_.invalid_frames++;
    }
    
    if (!info.crc_valid) {
        stats_.crc_errors++;
    }
    
    if (info.complete_message) {
        stats_.complete_messages++;
    } else {
        stats_.fragmented_messages++;
    }
    
    // 功能码统计
    stats_.function_code_counts[info.datalink_info.function_code]++;
    stats_.application_function_counts[info.application_info.function_code]++;
    
    // 地址统计
    stats_.source_address_counts[info.datalink_info.source]++;
    stats_.destination_address_counts[info.datalink_info.destination]++;
    
    // 安全统计
    if (info.security_analysis.critical_function_executed) {
        stats_.critical_operations++;
    }
    
    if (!info.security_analysis.security_issues.empty()) {
        stats_.security_violations++;
    }
    
    if (!info.anomalies.empty()) {
        stats_.anomaly_count++;
    }
}

DNP3Statistics DNP3DeepAnalyzer::get_statistics() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void DNP3DeepAnalyzer::reset_statistics() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = DNP3Statistics{};
}

std::string DNP3DeepAnalyzer::generate_security_report(const DNP3Info& info) const {
    std::stringstream report;
    
    report << "=== DNP3安全分析报告 ===\n";
    report << "时间戳: " << std::chrono::duration_cast<std::chrono::milliseconds>(
        info.parse_timestamp.time_since_epoch()).count() << "ms\n";
    report << "源地址: " << info.datalink_info.source << "\n";
    report << "目标地址: " << info.datalink_info.destination << "\n";
    report << "功能码: 0x" << std::hex << static_cast<int>(info.datalink_info.function_code) << std::dec << "\n";
    
    report << "\n=== 安全分析 ===\n";
    report << "安全评分: " << info.security_analysis.security_score << "/100\n";
    report << "风险级别: " << info.security_analysis.risk_level << "\n";
    
    if (!info.security_analysis.security_issues.empty()) {
        report << "发现的安全问题:\n";
        for (const auto& issue : info.security_analysis.security_issues) {
            report << "  - " << issue << "\n";
        }
    }
    
    if (!info.security_analysis.operational_risks.empty()) {
        report << "操作风险:\n";
        for (const auto& risk : info.security_analysis.operational_risks) {
            report << "  - " << risk << "\n";
        }
    }
    
    if (!info.anomalies.empty()) {
        report << "\n=== 异常检测 ===\n";
        for (const auto& anomaly : info.anomalies) {
            report << "  - " << anomaly << "\n";
        }
    }
    
    return report.str();
}

bool DNP3DeepAnalyzer::parse_dnp3_packet(const protocol_parser::core::BufferView& buffer, DNP3Info& dnp3_info) {
    if (!can_parse(buffer)) {
        return false;
    }
    
    // 重置信息结构
    dnp3_info = DNP3Info{};
    dnp3_info.parse_timestamp = std::chrono::steady_clock::now();
    
    // 解析数据链路层头
    if (!parse_datalink_header(buffer, dnp3_info.datalink_info)) {
        dnp3_info.parse_errors.push_back("Failed to parse datalink header");
        return false;
    }
    
    // 验证CRC
    if (!validate_datalink_crc(buffer)) {
        dnp3_info.crc_valid = false;
        dnp3_info.parse_errors.push_back("Datalink CRC validation failed");
        // 继续解析，但标记CRC错误
    } else {
        dnp3_info.crc_valid = true;
    }
    
    // 检查是否有传输层数据
    if (dnp3_info.datalink_info.length > 5) {
        size_t transport_offset = 10; // 数据链路层头大小
        size_t transport_length = std::min(buffer.size() - transport_offset, 
                                          static_cast<size_t>(dnp3_info.datalink_info.length - 5));
        
        if (transport_length > 0) {
            protocol_parser::core::BufferView transport_buffer(
                buffer.data() + transport_offset, transport_length);
            
            if (!parse_transport_header(transport_buffer, dnp3_info.transport_info)) {
                dnp3_info.parse_errors.push_back("Failed to parse transport header");
            } else {
                // 检查是否有应用层数据
                if (dnp3_info.transport_info.data.size() > 2) {
                    protocol_parser::core::BufferView app_buffer(
                        dnp3_info.transport_info.data.data(), 
                        dnp3_info.transport_info.data.size());
                    
                    if (!parse_application_header(app_buffer, dnp3_info.application_info)) {
                        dnp3_info.parse_errors.push_back("Failed to parse application header");
                    }
                }
            }
        }
    }
    
    // 执行深度分析
    if (security_monitoring_enabled_) {
        dnp3_info.security_analysis = analyze_security(dnp3_info);
    }
    
    if (anomaly_detection_enabled_) {
        if (detect_anomalies(dnp3_info)) {
            analyze_anomalies(dnp3_info);
        }
    }
    
    // 更新统计信息
    update_statistics(dnp3_info);
    
    // 检查是否为完整消息
    dnp3_info.complete_message = (dnp3_info.transport_info.fin && dnp3_info.transport_info.fir);
    dnp3_info.valid_frame = dnp3_info.parse_errors.empty();

    return true;
}

} // namespace protocol_parser::parsers::industrial