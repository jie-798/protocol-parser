#pragma once

#include "../../core/buffer_view.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>
#include <array>
#include <set>
#include <mutex>

namespace protocol_parser::parsers::industrial {

// DNP3数据链路层帧信息
struct DNP3DataLinkInfo {
    uint8_t start_byte_1 = 0;
    uint8_t start_byte_2 = 0;
    uint8_t length = 0;
    uint8_t control = 0;
    uint16_t destination = 0;
    uint16_t source = 0;
    uint16_t crc = 0;
    
    // 控制字段解析
    bool direction = false;         // 0=主站->从站, 1=从站->主站
    bool primary = false;           // 1=主帧, 0=次帧
    bool frame_count_bit = false;   // 帧计数位
    bool data_flow_control = false; // 数据流控制
    uint8_t function_code = 0;      // 功能码
};

// DNP3传输层信息
struct DNP3TransportInfo {
    bool fin = false;               // 最后一个分片
    bool fir = false;               // 第一个分片
    uint8_t sequence = 0;           // 序列号
    std::vector<uint8_t> data;      // 传输数据
};

// DNP3应用层信息
struct DNP3ApplicationInfo {
    uint8_t application_control = 0;
    uint8_t function_code = 0;
    uint16_t internal_indications = 0;
    
    // 应用控制字段
    bool fir = false;               // 第一个片段
    bool fin = false;               // 最后一个片段
    bool con = false;               // 确认
    bool uns = false;               // 未请求
    uint8_t sequence = 0;           // 序列号
    
    // 对象和变化
    std::vector<DNP3Object> objects;
};

// DNP3对象信息
struct DNP3Object {
    uint8_t group = 0;
    uint8_t variation = 0;
    uint8_t qualifier = 0;
    uint16_t range_start = 0;
    uint16_t range_stop = 0;
    std::vector<uint8_t> object_data;
    
    std::string get_object_name() const;
    std::string get_object_description() const;
};

// DNP3安全分析结果
struct DNP3SecurityAnalysis {
    bool authentication_enabled = false;
    bool secure_authentication = false;
    bool challenge_response_used = false;
    bool broadcast_detected = false;
    bool time_sync_detected = false;
    bool configuration_change = false;
    bool critical_function_executed = false;
    
    std::vector<std::string> security_issues;
    std::vector<std::string> operational_risks;
    uint32_t security_score = 50; // 0-100
    std::string risk_level = "MEDIUM";
    
    // 攻击检测
    bool dos_attack_detected = false;
    bool replay_attack_possible = false;
    bool unauthorized_commands = false;
    bool data_integrity_compromised = false;
};

// 完整的DNP3数据包信息
struct DNP3Info {
    std::chrono::steady_clock::time_point parse_timestamp;
    
    // 各层信息
    DNP3DataLinkInfo datalink_info;
    DNP3TransportInfo transport_info;
    DNP3ApplicationInfo application_info;
    
    // 解析状态
    bool valid_frame = false;
    bool complete_message = false;
    bool crc_valid = false;
    std::vector<std::string> parse_errors;
    
    // 安全分析
    DNP3SecurityAnalysis security_analysis;
    
    // 异常检测
    std::vector<std::string> anomalies;
    double anomaly_score = 0.0;
    
    // 统计信息
    size_t total_fragments = 0;
    size_t fragment_number = 0;
    size_t payload_size = 0;
};

// DNP3统计信息
struct DNP3Statistics {
    uint64_t total_frames = 0;
    uint64_t valid_frames = 0;
    uint64_t invalid_frames = 0;
    uint64_t crc_errors = 0;
    uint64_t fragmented_messages = 0;
    uint64_t complete_messages = 0;
    
    // 功能码统计
    std::unordered_map<uint8_t, uint64_t> function_code_counts;
    std::unordered_map<uint8_t, uint64_t> application_function_counts;
    
    // 对象统计
    std::unordered_map<std::string, uint64_t> object_type_counts;
    
    // 通信统计
    std::unordered_map<uint16_t, uint64_t> source_address_counts;
    std::unordered_map<uint16_t, uint64_t> destination_address_counts;
    
    // 安全统计
    uint64_t authentication_attempts = 0;
    uint64_t failed_authentications = 0;
    uint64_t security_violations = 0;
    uint64_t critical_operations = 0;
    
    // 异常统计
    uint64_t anomaly_count = 0;
    uint64_t dos_attempts = 0;
    uint64_t replay_attempts = 0;
};

// 高级DNP3深度分析器
class DNP3DeepAnalyzer {
public:
    DNP3DeepAnalyzer();
    ~DNP3DeepAnalyzer() = default;
    
    // 核心解析功能
    bool can_parse(const protocol_parser::core::BufferView& buffer) const;
    bool parse_dnp3_packet(const protocol_parser::core::BufferView& buffer, DNP3Info& dnp3_info);
    
    // 安全分析
    DNP3SecurityAnalysis analyze_security(const DNP3Info& info) const;
    bool detect_attack_patterns(const DNP3Info& info) const;
    bool detect_anomalies(const DNP3Info& info) const;
    
    // 配置管理
    void enable_security_monitoring(bool enabled) { security_monitoring_enabled_ = enabled; }
    void enable_anomaly_detection(bool enabled) { anomaly_detection_enabled_ = enabled; }
    void enable_deep_inspection(bool enabled) { deep_inspection_enabled_ = enabled; }
    void set_anomaly_threshold(double threshold) { anomaly_threshold_ = threshold; }
    
    // 统计和报告
    DNP3Statistics get_statistics() const;
    void reset_statistics();
    std::string generate_security_report(const DNP3Info& info) const;
    std::string generate_traffic_analysis() const;
    
    // 实时监控
    void add_monitored_address(uint16_t address) { monitored_addresses_.insert(address); }
    void remove_monitored_address(uint16_t address) { monitored_addresses_.erase(address); }
    void set_alert_callback(std::function<void(const DNP3Info&, const std::string&)> callback) {
        alert_callback_ = callback;
    }

private:
    // 配置选项
    bool security_monitoring_enabled_;
    bool anomaly_detection_enabled_;
    bool deep_inspection_enabled_;
    bool authentication_required_;
    double anomaly_threshold_;
    
    // 解析器状态
    std::unordered_map<uint16_t, std::vector<DNP3TransportInfo>> fragmented_messages_;
    std::chrono::steady_clock::time_point last_packet_time_;
    
    // 安全监控
    std::set<uint16_t> monitored_addresses_;
    std::set<uint16_t> authorized_masters_;
    std::set<uint16_t> authorized_outstations_;
    std::function<void(const DNP3Info&, const std::string&)> alert_callback_;
    
    // 统计信息
    mutable std::mutex stats_mutex_;
    DNP3Statistics stats_;
    
    // 对象定义映射
    std::unordered_map<std::string, std::string> object_definitions_;
    std::unordered_map<uint8_t, std::string> function_code_names_;
    std::unordered_map<uint8_t, std::string> application_function_names_;
    
    // 初始化方法
    void initialize_object_definitions();
    void initialize_function_codes();
    void initialize_security_settings();
    
    // 数据链路层解析
    bool parse_datalink_header(const protocol_parser::core::BufferView& buffer, DNP3DataLinkInfo& dl_info);
    bool validate_datalink_crc(const protocol_parser::core::BufferView& buffer) const;
    bool parse_datalink_control(uint8_t control, DNP3DataLinkInfo& dl_info);
    
    // 传输层解析
    bool parse_transport_header(const protocol_parser::core::BufferView& buffer, DNP3TransportInfo& transport_info);
    bool reassemble_fragments(const DNP3DataLinkInfo& dl_info, const DNP3TransportInfo& transport_info, 
                             std::vector<uint8_t>& complete_message);
    
    // 应用层解析
    bool parse_application_header(const protocol_parser::core::BufferView& buffer, DNP3ApplicationInfo& app_info);
    bool parse_application_objects(const protocol_parser::core::BufferView& buffer, DNP3ApplicationInfo& app_info);
    bool parse_object_header(const protocol_parser::core::BufferView& buffer, size_t& offset, DNP3Object& object);
    bool parse_object_data(const protocol_parser::core::BufferView& buffer, size_t& offset, DNP3Object& object);
    
    // CRC计算和验证
    uint16_t calculate_crc(const protocol_parser::core::BufferView& buffer) const;
    bool verify_block_crc(const protocol_parser::core::BufferView& buffer, size_t block_start) const;
    
    // 安全分析方法
    bool is_critical_function(uint8_t function_code) const;
    bool is_configuration_function(uint8_t function_code) const;
    bool detect_broadcast_abuse(const DNP3Info& info) const;
    bool detect_timing_attacks(const DNP3Info& info) const;
    bool detect_replay_attack(const DNP3Info& info) const;
    bool analyze_authentication(const DNP3Info& info) const;
    
    // 异常检测方法
    double calculate_packet_anomaly_score(const DNP3Info& info) const;
    bool detect_size_anomalies(const DNP3Info& info) const;
    bool detect_timing_anomalies(const DNP3Info& info) const;
    bool detect_sequence_anomalies(const DNP3Info& info) const;
    bool detect_content_anomalies(const DNP3Info& info) const;
    
    // 统计更新
    void update_statistics(const DNP3Info& info);
    void record_security_event(const std::string& event_type, const DNP3Info& info);
    
    // 实用工具方法
    std::string get_function_name(uint8_t function_code, bool is_application = false) const;
    std::string get_object_description(uint8_t group, uint8_t variation) const;
    uint32_t calculate_security_score(const DNP3SecurityAnalysis& analysis) const;
    std::string determine_risk_level(uint32_t security_score) const;
    
    // 预定义的CRC表
    static const std::array<uint16_t, 256> crc_table_;
};

} // namespace protocol_parser::parsers::industrial