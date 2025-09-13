#pragma once

#include "../../core/buffer_view.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>
#include <array>
#include <set>
#include <mutex>

namespace protocol_parser::parsers::security {

// IPSec协议类型
enum class IPSecProtocol {
    ESP = 50,    // Encapsulating Security Payload
    AH = 51,     // Authentication Header
    UNKNOWN = 0
};

// ESP头信息
struct ESPHeader {
    uint32_t spi = 0;           // Security Parameter Index
    uint32_t sequence = 0;      // 序列号
    std::vector<uint8_t> payload; // 加密载荷
    std::vector<uint8_t> padding; // 填充
    uint8_t pad_length = 0;     // 填充长度
    uint8_t next_header = 0;    // 下一个头类型
    std::vector<uint8_t> icv;   // Integrity Check Value
};

// AH头信息
struct AHHeader {
    uint8_t next_header = 0;    // 下一个头类型
    uint8_t payload_length = 0; // 载荷长度
    uint16_t reserved = 0;      // 保留字段
    uint32_t spi = 0;           // Security Parameter Index
    uint32_t sequence = 0;      // 序列号
    std::vector<uint8_t> icv;   // Integrity Check Value
};

// IKE（Internet Key Exchange）信息
struct IKEInfo {
    uint64_t initiator_spi = 0;
    uint64_t responder_spi = 0;
    uint8_t next_payload = 0;
    uint8_t version = 0;
    uint8_t exchange_type = 0;
    uint8_t flags = 0;
    uint32_t message_id = 0;
    uint32_t length = 0;
    
    // IKE载荷
    std::vector<IKEPayload> payloads;
};

// IKE载荷
struct IKEPayload {
    uint8_t next_payload = 0;
    bool critical = false;
    uint16_t payload_length = 0;
    uint8_t payload_type = 0;
    std::vector<uint8_t> payload_data;
    
    std::string get_payload_type_name() const;
};

// IPSec安全分析结果
struct IPSecSecurityAnalysis {
    // 加密强度分析
    std::string encryption_algorithm;
    std::string authentication_algorithm;
    uint32_t key_length = 0;
    bool strong_encryption = false;
    bool strong_authentication = false;
    
    // 协议安全性
    bool perfect_forward_secrecy = false;
    bool anti_replay_protection = false;
    bool tunnel_mode = false;
    bool transport_mode = false;
    
    // 检测到的问题
    std::vector<std::string> vulnerabilities;
    std::vector<std::string> security_warnings;
    std::vector<std::string> configuration_issues;
    
    // 安全评分
    uint32_t encryption_score = 0;      // 0-100
    uint32_t authentication_score = 0;  // 0-100
    uint32_t protocol_score = 0;        // 0-100
    uint32_t overall_security_score = 0; // 0-100
    std::string security_grade;          // A+, A, B, C, D, F
    
    // 攻击检测
    bool downgrade_attack_detected = false;
    bool replay_attack_detected = false;
    bool dos_attack_detected = false;
    bool mitm_attack_possible = false;
};

// 完整的IPSec信息
struct IPSecInfo {
    std::chrono::steady_clock::time_point parse_timestamp;
    
    // 协议信息
    IPSecProtocol protocol_type = IPSecProtocol::UNKNOWN;
    ESPHeader esp_header;
    AHHeader ah_header;
    IKEInfo ike_info;
    
    // 解析状态
    bool valid_packet = false;
    bool encrypted_payload = false;
    bool authentication_verified = false;
    std::vector<std::string> parse_errors;
    
    // 安全分析
    IPSecSecurityAnalysis security_analysis;
    
    // 流量分析
    uint32_t flow_id = 0;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    
    // 异常检测
    std::vector<std::string> anomalies;
    double anomaly_score = 0.0;
    
    // 性能指标
    size_t packet_size = 0;
    double processing_time_ms = 0.0;
};

// IPSec统计信息
struct IPSecStatistics {
    uint64_t total_packets = 0;
    uint64_t esp_packets = 0;
    uint64_t ah_packets = 0;
    uint64_t ike_packets = 0;
    uint64_t valid_packets = 0;
    uint64_t invalid_packets = 0;
    uint64_t encrypted_packets = 0;
    uint64_t authenticated_packets = 0;
    
    // 安全统计
    std::unordered_map<std::string, uint64_t> encryption_algorithm_counts;
    std::unordered_map<std::string, uint64_t> authentication_algorithm_counts;
    std::unordered_map<uint32_t, uint64_t> spi_usage_counts;
    
    // 攻击统计
    uint64_t replay_attacks = 0;
    uint64_t downgrade_attacks = 0;
    uint64_t dos_attempts = 0;
    uint64_t mitm_attempts = 0;
    
    // 性能统计
    double avg_processing_time_ms = 0.0;
    double min_processing_time_ms = 0.0;
    double max_processing_time_ms = 0.0;
    
    // 流量统计
    std::unordered_map<std::string, uint64_t> tunnel_endpoint_counts;
    uint64_t total_encrypted_bytes = 0;
    uint64_t total_authenticated_bytes = 0;
};

// 高级IPSec深度分析器
class IPSecDeepAnalyzer {
public:
    IPSecDeepAnalyzer();
    ~IPSecDeepAnalyzer() = default;
    
    // 核心解析功能
    bool can_parse(const protocol_parser::core::BufferView& buffer, uint8_t protocol) const;
    bool parse_ipsec_packet(const protocol_parser::core::BufferView& buffer, uint8_t protocol, IPSecInfo& ipsec_info);
    
    // 安全分析
    IPSecSecurityAnalysis analyze_security(const IPSecInfo& info) const;
    bool detect_downgrade_attack(const IPSecInfo& info) const;
    bool detect_replay_attack(const IPSecInfo& info) const;
    bool detect_dos_attack(const IPSecInfo& info) const;
    bool analyze_encryption_strength(const IPSecInfo& info) const;
    
    // 配置管理
    void enable_deep_inspection(bool enabled) { deep_inspection_enabled_ = enabled; }
    void enable_attack_detection(bool enabled) { attack_detection_enabled_ = enabled; }
    void enable_flow_analysis(bool enabled) { flow_analysis_enabled_ = enabled; }
    void set_security_policy(const std::string& policy) { security_policy_ = policy; }
    
    // 统计和报告
    IPSecStatistics get_statistics() const;
    void reset_statistics();
    std::string generate_security_report(const IPSecInfo& info) const;
    std::string generate_tunnel_analysis() const;
    std::string generate_threat_assessment() const;
    
    // 实时监控
    void add_monitored_spi(uint32_t spi) { monitored_spis_.insert(spi); }
    void remove_monitored_spi(uint32_t spi) { monitored_spis_.erase(spi); }
    void set_security_alert_callback(std::function<void(const IPSecInfo&, const std::string&)> callback) {
        security_alert_callback_ = callback;
    }

private:
    // 配置选项
    bool deep_inspection_enabled_;
    bool attack_detection_enabled_;
    bool flow_analysis_enabled_;
    bool strict_validation_;
    std::string security_policy_;
    
    // 安全上下文
    std::unordered_map<uint32_t, SecurityAssociation> security_associations_;
    std::set<uint32_t> monitored_spis_;
    std::unordered_map<uint32_t, uint32_t> replay_windows_;
    
    // 攻击检测状态
    std::unordered_map<std::string, std::vector<std::chrono::steady_clock::time_point>> dos_detection_state_;
    std::unordered_map<uint32_t, uint32_t> sequence_tracking_;
    std::chrono::steady_clock::time_point last_packet_time_;
    
    // 回调函数
    std::function<void(const IPSecInfo&, const std::string&)> security_alert_callback_;
    
    // 统计信息
    mutable std::mutex stats_mutex_;
    IPSecStatistics stats_;
    
    // 算法定义
    std::unordered_map<uint8_t, std::string> encryption_algorithms_;
    std::unordered_map<uint8_t, std::string> authentication_algorithms_;
    std::unordered_map<uint8_t, uint32_t> algorithm_key_lengths_;
    std::unordered_map<uint8_t, std::string> ike_payload_types_;
    
    // 安全关联
    struct SecurityAssociation {
        uint32_t spi = 0;
        std::string encryption_algorithm;
        std::string authentication_algorithm;
        uint32_t key_length = 0;
        bool tunnel_mode = false;
        std::chrono::steady_clock::time_point creation_time;
        uint64_t bytes_processed = 0;
        uint32_t sequence_number = 0;
        uint32_t replay_window = 0;
    };
    
    // 初始化方法
    void initialize_algorithm_definitions();
    void initialize_security_policies();
    void initialize_attack_detection();
    
    // ESP解析
    bool parse_esp_header(const protocol_parser::core::BufferView& buffer, ESPHeader& esp_header);
    bool parse_esp_trailer(const protocol_parser::core::BufferView& buffer, ESPHeader& esp_header);
    bool decrypt_esp_payload(const ESPHeader& esp_header, const SecurityAssociation& sa);
    
    // AH解析
    bool parse_ah_header(const protocol_parser::core::BufferView& buffer, AHHeader& ah_header);
    bool verify_ah_authentication(const AHHeader& ah_header, const SecurityAssociation& sa);
    
    // IKE解析
    bool parse_ike_header(const protocol_parser::core::BufferView& buffer, IKEInfo& ike_info);
    bool parse_ike_payloads(const protocol_parser::core::BufferView& buffer, IKEInfo& ike_info);
    bool parse_ike_payload(const protocol_parser::core::BufferView& buffer, size_t& offset, IKEPayload& payload);
    
    // 安全分析方法
    bool is_strong_encryption(const std::string& algorithm, uint32_t key_length) const;
    bool is_strong_authentication(const std::string& algorithm) const;
    bool has_known_vulnerabilities(const std::string& algorithm) const;
    uint32_t calculate_encryption_score(const std::string& algorithm, uint32_t key_length) const;
    uint32_t calculate_authentication_score(const std::string& algorithm) const;
    uint32_t calculate_protocol_score(const IPSecInfo& info) const;
    std::string determine_security_grade(uint32_t overall_score) const;
    
    // 攻击检测方法
    bool check_replay_attack(uint32_t spi, uint32_t sequence) const;
    bool check_dos_patterns(const std::string& source_ip) const;
    bool check_downgrade_attempt(const IKEInfo& ike_info) const;
    bool analyze_traffic_patterns(const IPSecInfo& info) const;
    
    // 异常检测
    double calculate_anomaly_score(const IPSecInfo& info) const;
    bool detect_size_anomalies(const IPSecInfo& info) const;
    bool detect_timing_anomalies(const IPSecInfo& info) const;
    bool detect_protocol_anomalies(const IPSecInfo& info) const;
    
    // 统计更新
    void update_statistics(const IPSecInfo& info);
    void update_security_association(uint32_t spi, const IPSecInfo& info);
    void record_attack_attempt(const std::string& attack_type, const IPSecInfo& info);
    
    // 实用工具
    std::string get_encryption_algorithm_name(uint8_t algorithm_id) const;
    std::string get_authentication_algorithm_name(uint8_t algorithm_id) const;
    std::string get_ike_payload_type_name(uint8_t payload_type) const;
    bool is_weak_algorithm(const std::string& algorithm) const;
    bool is_deprecated_algorithm(const std::string& algorithm) const;
};

} // namespace protocol_parser::parsers::security