#pragma once

#include "../../core/buffer_view.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <atomic>
#include <mutex>

namespace protocol_parser::industrial {

// Modbus协议变体
enum class ModbusVariant {
    RTU,        // Modbus RTU
    ASCII,      // Modbus ASCII  
    TCP,        // Modbus TCP
    UDP         // Modbus UDP
};

// Modbus功能码
enum class ModbusFunctionCode : uint8_t {
    READ_COILS = 0x01,
    READ_DISCRETE_INPUTS = 0x02,
    READ_HOLDING_REGISTERS = 0x03,
    READ_INPUT_REGISTERS = 0x04,
    WRITE_SINGLE_COIL = 0x05,
    WRITE_SINGLE_REGISTER = 0x06,
    READ_EXCEPTION_STATUS = 0x07,
    DIAGNOSTICS = 0x08,
    GET_COMM_EVENT_COUNTER = 0x0B,
    GET_COMM_EVENT_LOG = 0x0C,
    WRITE_MULTIPLE_COILS = 0x0F,
    WRITE_MULTIPLE_REGISTERS = 0x10,
    REPORT_SLAVE_ID = 0x11,
    READ_FILE_RECORD = 0x14,
    WRITE_FILE_RECORD = 0x15,
    MASK_WRITE_REGISTER = 0x16,
    READ_WRITE_MULTIPLE_REGISTERS = 0x17,
    READ_FIFO_QUEUE = 0x18,
    ENCAPSULATED_INTERFACE_TRANSPORT = 0x2B,
    EXCEPTION_RESPONSE = 0x80
};

// Modbus异常码
enum class ModbusExceptionCode : uint8_t {
    ILLEGAL_FUNCTION = 0x01,
    ILLEGAL_DATA_ADDRESS = 0x02,
    ILLEGAL_DATA_VALUE = 0x03,
    SLAVE_DEVICE_FAILURE = 0x04,
    ACKNOWLEDGE = 0x05,
    SLAVE_DEVICE_BUSY = 0x06,
    NEGATIVE_ACKNOWLEDGE = 0x07,
    MEMORY_PARITY_ERROR = 0x08,
    GATEWAY_PATH_UNAVAILABLE = 0x0A,
    GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND = 0x0B
};

// Modbus MBAP头部 (TCP)
struct ModbusMBAPHeader {
    uint16_t transaction_id;    // 事务标识符
    uint16_t protocol_id;       // 协议标识符 (通常为0)
    uint16_t length;           // 长度字段
    uint8_t unit_id;           // 单元标识符
};

// Modbus PDU (协议数据单元)
struct ModbusPDU {
    ModbusFunctionCode function_code;
    std::vector<uint8_t> data;
    bool is_exception = false;
    ModbusExceptionCode exception_code = ModbusExceptionCode::ILLEGAL_FUNCTION;
};

// Modbus寄存器值
struct ModbusRegister {
    uint16_t address;
    uint16_t value;
    std::chrono::system_clock::time_point timestamp;
    bool is_valid = true;
    
    // 数据类型解释
    int16_t as_int16() const { return static_cast<int16_t>(value); }
    float as_float() const { 
        // 简化的浮点转换，实际需要考虑字节序和IEEE 754格式
        union { uint16_t i; float f; } u;
        u.i = value;
        return u.f;
    }
};

// Modbus线圈值
struct ModbusCoil {
    uint16_t address;
    bool value;
    std::chrono::system_clock::time_point timestamp;
    bool is_valid = true;
};

// Modbus设备信息
struct ModbusDevice {
    uint8_t slave_id = 0;
    std::string vendor_name;
    std::string product_code;
    std::string version;
    std::string device_name;
    std::vector<uint8_t> additional_data;
    std::chrono::system_clock::time_point last_seen;
    bool is_online = false;
    uint32_t message_count = 0;
    uint32_t error_count = 0;
    
    [[nodiscard]] double get_error_rate() const {
        return message_count > 0 ? static_cast<double>(error_count) / message_count : 0.0;
    }
};

// Modbus安全分析
struct ModbusSecurityAnalysis {
    bool is_secure = false;  // Modbus本身缺乏安全性
    std::vector<std::string> vulnerabilities;
    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;
    
    bool no_authentication = true;   // Modbus没有认证
    bool no_encryption = true;       // Modbus没有加密
    bool broadcast_detected = false;
    bool unauthorized_access = false;
    bool suspicious_function_codes = false;
    bool abnormal_traffic_pattern = false;
    bool potential_replay_attack = false;
    bool potential_dos_attack = false;
    bool scan_detected = false;      // 检测到扫描行为
    
    uint32_t security_score = 30;    // Modbus基础安全性很低
    std::string risk_level = "HIGH"; // HIGH, MEDIUM, LOW
};

// Modbus统计信息快照（可复制）
struct ModbusStatisticsSnapshot {
    uint64_t total_requests{0};
    uint64_t total_responses{0};
    uint64_t read_requests{0};
    uint64_t write_requests{0};
    uint64_t exception_responses{0};
    uint64_t timeout_errors{0};
    uint64_t crc_errors{0};
    uint64_t frame_errors{0};
    uint64_t bytes_transmitted{0};
    uint64_t bytes_received{0};

    std::chrono::system_clock::time_point last_activity;
    std::chrono::milliseconds avg_response_time{0};

    // 功能码统计
    std::unordered_map<uint8_t, uint64_t> function_code_counts;
    std::unordered_map<uint8_t, uint64_t> slave_message_counts;
    std::unordered_map<uint8_t, uint64_t> exception_counts;
};

// Modbus统计信息（线程安全，使用atomic）
struct ModbusStatistics {
    std::atomic<uint64_t> total_requests{0};
    std::atomic<uint64_t> total_responses{0};
    std::atomic<uint64_t> read_requests{0};
    std::atomic<uint64_t> write_requests{0};
    std::atomic<uint64_t> exception_responses{0};
    std::atomic<uint64_t> timeout_errors{0};
    std::atomic<uint64_t> crc_errors{0};
    std::atomic<uint64_t> frame_errors{0};
    std::atomic<uint64_t> bytes_transmitted{0};
    std::atomic<uint64_t> bytes_received{0};

    std::chrono::system_clock::time_point last_activity;
    std::chrono::milliseconds avg_response_time{0};

    // 功能码统计（需要外部同步）
    std::unordered_map<uint8_t, uint64_t> function_code_counts;
    std::unordered_map<uint8_t, uint64_t> slave_message_counts;
    std::unordered_map<uint8_t, uint64_t> exception_counts;

    // 创建快照（线程安全地复制）
    [[nodiscard]] ModbusStatisticsSnapshot snapshot() const {
        ModbusStatisticsSnapshot snap;
        snap.total_requests = total_requests.load();
        snap.total_responses = total_responses.load();
        snap.read_requests = read_requests.load();
        snap.write_requests = write_requests.load();
        snap.exception_responses = exception_responses.load();
        snap.timeout_errors = timeout_errors.load();
        snap.crc_errors = crc_errors.load();
        snap.frame_errors = frame_errors.load();
        snap.bytes_transmitted = bytes_transmitted.load();
        snap.bytes_received = bytes_received.load();
        snap.last_activity = last_activity;
        snap.avg_response_time = avg_response_time;
        snap.function_code_counts = function_code_counts;
        snap.slave_message_counts = slave_message_counts;
        snap.exception_counts = exception_counts;
        return snap;
    }

    void record_request(ModbusFunctionCode fc, uint8_t slave_id) {
        total_requests++;
        if (is_read_function(fc)) {
            read_requests++;
        } else if (is_write_function(fc)) {
            write_requests++;
        }
        function_code_counts[static_cast<uint8_t>(fc)]++;
        slave_message_counts[slave_id]++;
        last_activity = std::chrono::system_clock::now();
    }

    void record_response(bool success) {
        total_responses++;
        if (!success) {
            exception_responses++;
        }
    }

    void record_exception(ModbusExceptionCode code) {
        exception_responses++;
        exception_counts[static_cast<uint8_t>(code)]++;
    }
    
    [[nodiscard]] double get_error_rate() const {
        return total_requests > 0 ? 
            static_cast<double>(exception_responses) / total_requests : 0.0;
    }
    
    [[nodiscard]] double get_response_rate() const {
        return total_requests > 0 ? 
            static_cast<double>(total_responses) / total_requests : 0.0;
    }

private:
    static bool is_read_function(ModbusFunctionCode fc) {
        return fc == ModbusFunctionCode::READ_COILS ||
               fc == ModbusFunctionCode::READ_DISCRETE_INPUTS ||
               fc == ModbusFunctionCode::READ_HOLDING_REGISTERS ||
               fc == ModbusFunctionCode::READ_INPUT_REGISTERS;
    }
    
    static bool is_write_function(ModbusFunctionCode fc) {
        return fc == ModbusFunctionCode::WRITE_SINGLE_COIL ||
               fc == ModbusFunctionCode::WRITE_SINGLE_REGISTER ||
               fc == ModbusFunctionCode::WRITE_MULTIPLE_COILS ||
               fc == ModbusFunctionCode::WRITE_MULTIPLE_REGISTERS;
    }
};

// Modbus解析信息
struct ModbusInfo {
    ModbusVariant variant = ModbusVariant::TCP;

    // MBAP头部直接访问（为了兼容性）
    uint16_t transaction_id = 0;
    uint16_t protocol_id = 0;
    uint16_t length = 0;
    uint8_t unit_id = 0;

    // TCP特有
    ModbusMBAPHeader mbap_header;

    // PDU直接访问（为了兼容性）
    uint8_t function_code = 0;
    bool is_exception = false;
    uint8_t exception_code = 0;
    std::string exception_description;

    // PDU
    ModbusPDU pdu;

    // RTU/ASCII特有
    uint8_t slave_id = 0;
    uint16_t crc = 0;
    uint8_t lrc = 0;  // ASCII模式的LRC校验

    // 解析的数据
    std::vector<ModbusCoil> coils;
    std::vector<ModbusRegister> registers;
    std::vector<bool> coil_values;
    std::vector<uint16_t> register_values;
    std::vector<uint8_t> data_payload;
    std::vector<std::string> validation_errors;
    std::vector<std::string> anomalies;

    // 设备信息
    ModbusDevice device_info;

    // 请求/响应信息
    bool is_request = true;
    bool is_broadcast = false;
    uint16_t start_address = 0;
    uint16_t starting_address = 0;  // 别名，兼容旧代码
    uint16_t quantity = 0;
    uint16_t register_count = 0;
    uint16_t and_mask = 0;
    uint16_t or_mask = 0;
    uint16_t read_starting_address = 0;
    uint16_t read_quantity = 0;
    uint8_t mei_type = 0;
    uint8_t device_id_code = 0;
    uint8_t object_id = 0;

    // 连接信息
    std::string master_ip;
    std::string slave_ip;
    uint16_t master_port = 0;
    uint16_t slave_port = 502;  // Modbus TCP默认端口

    // 统计和安全
    ModbusStatistics statistics;
    ModbusSecurityAnalysis security_analysis;

    // 原始数据
    std::vector<uint8_t> raw_data;

    // 元数据
    bool is_valid = false;
    std::string error_message;
    std::chrono::steady_clock::time_point parse_timestamp;
    uint32_t flow_id = 0;
    
    [[nodiscard]] std::string get_function_name() const {
        switch (pdu.function_code) {
            case ModbusFunctionCode::READ_COILS: return "Read Coils";
            case ModbusFunctionCode::READ_DISCRETE_INPUTS: return "Read Discrete Inputs";
            case ModbusFunctionCode::READ_HOLDING_REGISTERS: return "Read Holding Registers";
            case ModbusFunctionCode::READ_INPUT_REGISTERS: return "Read Input Registers";
            case ModbusFunctionCode::WRITE_SINGLE_COIL: return "Write Single Coil";
            case ModbusFunctionCode::WRITE_SINGLE_REGISTER: return "Write Single Register";
            case ModbusFunctionCode::WRITE_MULTIPLE_COILS: return "Write Multiple Coils";
            case ModbusFunctionCode::WRITE_MULTIPLE_REGISTERS: return "Write Multiple Registers";
            case ModbusFunctionCode::DIAGNOSTICS: return "Diagnostics";
            case ModbusFunctionCode::REPORT_SLAVE_ID: return "Report Slave ID";
            default: return "Unknown Function";
        }
    }
    
    [[nodiscard]] bool is_critical_function() const {
        return pdu.function_code == ModbusFunctionCode::WRITE_SINGLE_COIL ||
               pdu.function_code == ModbusFunctionCode::WRITE_SINGLE_REGISTER ||
               pdu.function_code == ModbusFunctionCode::WRITE_MULTIPLE_COILS ||
               pdu.function_code == ModbusFunctionCode::WRITE_MULTIPLE_REGISTERS;
    }
};

// Modbus深度解析器
class ModbusDeepAnalyzer {
public:
    ModbusDeepAnalyzer();
    ~ModbusDeepAnalyzer() = default;

    // 主要解析方法
    bool parse_modbus_packet(const protocol_parser::core::BufferView& buffer, ModbusInfo& modbus_info);
    
    // 协议检测
    bool can_parse(const protocol_parser::core::BufferView& buffer) const;
    ModbusVariant detect_variant(const protocol_parser::core::BufferView& buffer) const;
    
    // 安全分析
    ModbusSecurityAnalysis analyze_security(const ModbusInfo& info) const;
    std::vector<std::string> detect_vulnerabilities(const ModbusInfo& info) const;
    std::vector<std::string> detect_anomalies(const ModbusInfo& info) const;
    uint32_t calculate_security_score(const ModbusInfo& info) const;
    
    // 设备管理
    void register_device(const ModbusDevice& device);
    ModbusDevice* find_device(uint8_t slave_id);
    std::vector<ModbusDevice> get_known_devices() const;
    void update_device_status(uint8_t slave_id, bool online);
    
    // 异常检测
    bool detect_scan_attempt(const ModbusInfo& info) const;
    bool detect_unauthorized_access(const ModbusInfo& info) const;
    bool detect_replay_attack(const ModbusInfo& info) const;
    bool detect_dos_attempt(const ModbusInfo& info) const;
    
    // 配置
    void set_security_monitoring_enabled(bool enabled) { security_monitoring_enabled_ = enabled; }
    void set_device_discovery_enabled(bool enabled) { device_discovery_enabled_ = enabled; }
    void set_anomaly_detection_enabled(bool enabled) { anomaly_detection_enabled_ = enabled; }
    void set_crc_validation_enabled(bool enabled) { crc_validation_enabled_ = enabled; }
    
    // 统计和报告
    ModbusStatisticsSnapshot get_global_statistics() const { return global_stats_.snapshot(); }
    void reset_statistics();
    std::string generate_security_report() const;
    std::string generate_device_report() const;

private:
    bool security_monitoring_enabled_ = true;
    bool device_discovery_enabled_ = true;
    bool anomaly_detection_enabled_ = true;
    bool crc_validation_enabled_ = true;

    ModbusStatistics global_stats_;
    std::unordered_map<uint8_t, ModbusDevice> known_devices_;

    // 扫描检测
    bool real_time_analysis_ = true;
    size_t max_scan_requests_ = 100;
    std::chrono::milliseconds scan_time_window_{5000};
    double anomaly_threshold_ = 0.8;

    // 扫描尝试记录
    struct ScanAttempt {
        std::chrono::steady_clock::time_point timestamp;
        uint8_t unit_id;
        uint8_t function_code;
        uint16_t starting_address;
    };

    // 内部统计信息（用于替代global_stats_的部分功能）
    struct InternalStats {
        uint64_t total_packets = 0;
        uint64_t read_operations = 0;
        uint64_t write_operations = 0;
        uint64_t exception_count = 0;
        uint64_t anomaly_count = 0;
        uint64_t scan_attempts = 0;
        std::unordered_map<uint8_t, uint64_t> function_code_counts;
        std::unordered_map<uint8_t, uint64_t> unit_id_counts;
        std::unordered_map<uint8_t, uint64_t> exception_code_counts;
    } internal_stats_;

    mutable std::mutex stats_mutex_;
    mutable std::chrono::steady_clock::time_point last_packet_time_;
    mutable std::vector<ScanAttempt> scan_attempts_;  // mutable以便在const方法中修改

    // 合法功能码集合
    std::unordered_set<uint8_t> valid_function_codes_;

    // 异常码映射
    std::unordered_map<uint8_t, std::string> exception_codes_;

    // 内部解析方法
    bool parse_modbus_tcp(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_modbus_rtu(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_modbus_ascii(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);

    bool parse_mbap_header(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_pdu(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);

    // 功能码解析
    bool parse_read_bits_request(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_read_registers_request(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_write_single_coil(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_write_single_register(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_write_multiple_coils(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_write_multiple_registers(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_mask_write_register(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_read_write_multiple_registers(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_read_device_identification(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_function_specific_data(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);
    bool parse_exception_response(const protocol_parser::core::BufferView& buffer, ModbusInfo& info);

    // 校验方法
    bool verify_crc(const protocol_parser::core::BufferView& buffer) const;
    bool verify_lrc(const protocol_parser::core::BufferView& buffer) const;
    uint16_t calculate_crc(const protocol_parser::core::BufferView& buffer) const;
    uint8_t calculate_lrc(const protocol_parser::core::BufferView& buffer) const;

    // 安全分析内部方法
    void analyze_traffic_patterns(const ModbusInfo& info, ModbusSecurityAnalysis& analysis) const;
    void analyze_function_codes(const ModbusInfo& info, ModbusSecurityAnalysis& analysis) const;
    void analyze_access_patterns(const ModbusInfo& info, ModbusSecurityAnalysis& analysis) const;
    void check_for_attacks(const ModbusInfo& info, ModbusSecurityAnalysis& analysis) const;

    // 异常检测内部方法
    void analyze_anomalies(ModbusInfo& info) const;
    bool is_suspicious_function_code(ModbusFunctionCode fc) const;
    bool is_high_frequency_request(uint8_t slave_id) const;
    bool is_unusual_register_access(uint16_t start_addr, uint16_t count) const;
    bool is_valid_function_code(uint8_t function_code) const;
    bool is_write_function(uint8_t function_code) const;
    bool is_critical_address(uint16_t address) const;
    uint32_t calculate_security_score(const ModbusSecurityAnalysis& analysis) const;

    // 统计信息更新
    void update_statistics(const ModbusInfo& info);
    InternalStats get_statistics() const;

    // 工具方法
    std::string get_exception_name(ModbusExceptionCode code) const;
    std::string get_variant_name(ModbusVariant variant) const;
    bool is_broadcast_address(uint8_t slave_id) const { return slave_id == 0; }
    std::string generate_security_report(const ModbusInfo& info) const;

    // 常量定义
    static constexpr uint16_t MODBUS_TCP_HEADER_SIZE = 7;
    static constexpr uint16_t MODBUS_RTU_MIN_SIZE = 4;
    static constexpr uint16_t MODBUS_ASCII_MIN_SIZE = 9;
    static constexpr uint16_t MODBUS_TCP_DEFAULT_PORT = 502;
    static constexpr uint16_t MODBUS_PROTOCOL_ID = 0;
    static constexpr uint8_t MODBUS_BROADCAST_ID = 0;
    static constexpr char MODBUS_ASCII_START = ':';
    static constexpr char MODBUS_ASCII_END_CR = '\r';
    static constexpr char MODBUS_ASCII_END_LF = '\n';

    // 异常检测阈值
    static constexpr uint32_t MAX_REQUESTS_PER_SECOND = 100;
    static constexpr uint32_t MAX_REGISTER_COUNT = 125;
    static constexpr double MAX_ERROR_RATE = 0.1;  // 10%
};

} // namespace protocol_parser::industrial