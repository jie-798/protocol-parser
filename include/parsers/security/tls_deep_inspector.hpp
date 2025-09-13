#pragma once

#include "../core/buffer_view.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <array>

namespace protocol_parser::security {

// TLS版本定义
enum class TLSVersion : uint16_t {
    SSLv3 = 0x0300,
    TLS1_0 = 0x0301,
    TLS1_1 = 0x0302,
    TLS1_2 = 0x0303,
    TLS1_3 = 0x0304
};

// TLS记录类型
enum class TLSRecordType : uint8_t {
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23,
    HEARTBEAT = 24
};

// TLS握手消息类型
enum class TLSHandshakeType : uint8_t {
    HELLO_REQUEST = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    NEW_SESSION_TICKET = 4,
    END_OF_EARLY_DATA = 5,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE = 16,
    FINISHED = 20,
    KEY_UPDATE = 24
};

// TLS扩展类型
enum class TLSExtensionType : uint16_t {
    SERVER_NAME = 0,
    MAX_FRAGMENT_LENGTH = 1,
    STATUS_REQUEST = 5,
    SUPPORTED_GROUPS = 10,
    EC_POINT_FORMATS = 11,
    SIGNATURE_ALGORITHMS = 13,
    USE_SRTP = 14,
    HEARTBEAT = 15,
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,
    SIGNED_CERTIFICATE_TIMESTAMP = 18,
    PADDING = 21,
    ENCRYPT_THEN_MAC = 22,
    EXTENDED_MASTER_SECRET = 23,
    COMPRESS_CERTIFICATE = 27,
    PRE_SHARED_KEY = 41,
    EARLY_DATA = 42,
    SUPPORTED_VERSIONS = 43,
    COOKIE = 44,
    PSK_KEY_EXCHANGE_MODES = 45,
    CERTIFICATE_AUTHORITIES = 47,
    OID_FILTERS = 48,
    POST_HANDSHAKE_AUTH = 49,
    SIGNATURE_ALGORITHMS_CERT = 50,
    KEY_SHARE = 51,
    RENEGOTIATION_INFO = 65281
};

// 密码套件信息
struct TLSCipherSuite {
    uint16_t id;
    std::string name;
    std::string key_exchange;
    std::string authentication;
    std::string encryption;
    std::string mac;
    bool is_aead;
    uint16_t key_length;
    uint16_t iv_length;
    uint16_t mac_length;
    bool supports_pfs;  // Perfect Forward Secrecy
    uint8_t security_level;  // 1-5级安全等级
};

// TLS扩展信息
struct TLSExtension {
    TLSExtensionType type;
    uint16_t length;
    std::vector<uint8_t> data;
    
    // 解析后的扩展数据
    std::string server_name;
    std::vector<std::string> alpn_protocols;
    std::vector<uint16_t> supported_groups;
    std::vector<uint8_t> ec_point_formats;
    std::vector<uint16_t> signature_algorithms;
    TLSVersion max_version;
    TLSVersion min_version;
};

// TLS证书信息
struct TLSCertificate {
    std::vector<uint8_t> raw_data;
    std::string subject;
    std::string issuer;
    std::string serial_number;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    std::vector<std::string> subject_alt_names;
    std::string public_key_algorithm;
    uint16_t public_key_size;
    std::string signature_algorithm;
    std::vector<std::string> key_usage;
    bool is_ca;
    bool is_self_signed;
    bool is_expired;
    bool is_revoked;
    uint8_t trust_level;  // 0-100信任度
};

// TLS会话信息
struct TLSSession {
    std::vector<uint8_t> session_id;
    std::vector<uint8_t> session_ticket;
    TLSCipherSuite cipher_suite;
    std::chrono::system_clock::time_point creation_time;
    std::chrono::system_clock::time_point last_access_time;
    uint32_t lifetime_seconds;
    bool is_resumable;
    bool has_early_data;
    uint64_t bytes_transferred;
};

// TLS安全分析结果
struct TLSSecurityAnalysis {
    bool is_secure = true;
    std::vector<std::string> vulnerabilities;
    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;
    
    // 协议分析
    bool uses_weak_protocol = false;
    bool uses_deprecated_cipher = false;
    bool uses_weak_key_exchange = false;
    bool has_certificate_issues = false;
    bool allows_renegotiation = false;
    bool vulnerable_to_downgrade = false;
    bool compression_enabled = false;
    
    // 证书分析
    bool cert_expired = false;
    bool cert_self_signed = false;
    bool cert_weak_signature = false;
    bool cert_name_mismatch = false;
    bool cert_revoked = false;
    bool cert_chain_incomplete = false;
    
    // 配置分析
    bool perfect_forward_secrecy = false;
    bool secure_renegotiation = false;
    bool heartbeat_enabled = false;
    bool sni_enabled = false;
    bool ocsp_stapling = false;
    
    // 漏洞检测
    bool heartbleed_vulnerable = false;
    bool poodle_vulnerable = false;
    bool beast_vulnerable = false;
    bool crime_vulnerable = false;
    bool breach_vulnerable = false;
    bool lucky13_vulnerable = false;
    bool freak_vulnerable = false;
    bool logjam_vulnerable = false;
    
    uint32_t security_score = 0;  // 0-100安全评分
    std::string security_grade;   // A+, A, B, C, D, F
};

// TLS握手状态跟踪
struct TLSHandshakeState {
    bool client_hello_seen = false;
    bool server_hello_seen = false;
    bool certificate_seen = false;
    bool server_key_exchange_seen = false;
    bool certificate_request_seen = false;
    bool server_hello_done_seen = false;
    bool client_key_exchange_seen = false;
    bool certificate_verify_seen = false;
    bool client_finished_seen = false;
    bool server_finished_seen = false;
    bool change_cipher_spec_seen = false;
    
    // TLS 1.3特有状态
    bool encrypted_extensions_seen = false;
    bool new_session_ticket_seen = false;
    bool end_of_early_data_seen = false;
    bool key_update_seen = false;
    
    bool is_resumption = false;
    bool is_renegotiation = false;
    bool has_early_data = false;
    
    std::chrono::steady_clock::time_point handshake_start_time;
    std::chrono::steady_clock::time_point handshake_end_time;
    std::chrono::milliseconds handshake_duration{0};
    
    [[nodiscard]] bool is_complete() const {
        return client_finished_seen && server_finished_seen;
    }
    
    [[nodiscard]] double get_completion_percentage() const {
        int completed = 0;
        int total = 10;
        
        if (client_hello_seen) completed++;
        if (server_hello_seen) completed++;
        if (certificate_seen) completed++;
        if (server_key_exchange_seen) completed++;
        if (certificate_request_seen) completed++;
        if (server_hello_done_seen) completed++;
        if (client_key_exchange_seen) completed++;
        if (certificate_verify_seen) completed++;
        if (client_finished_seen) completed++;
        if (server_finished_seen) completed++;
        
        return static_cast<double>(completed) / total * 100.0;
    }
};

// TLS统计信息
struct TLSStatistics {
    std::atomic<uint64_t> total_connections{0};
    std::atomic<uint64_t> successful_handshakes{0};
    std::atomic<uint64_t> failed_handshakes{0};
    std::atomic<uint64_t> session_resumptions{0};
    std::atomic<uint64_t> renegotiations{0};
    std::atomic<uint64_t> total_bytes_encrypted{0};
    std::atomic<uint64_t> total_bytes_decrypted{0};
    std::atomic<uint64_t> handshake_messages{0};
    std::atomic<uint64_t> application_messages{0};
    std::atomic<uint64_t> alert_messages{0};
    std::atomic<uint64_t> heartbeat_messages{0};
    
    std::chrono::steady_clock::time_point last_activity;
    std::chrono::milliseconds avg_handshake_time{0};
    
    // 版本统计
    std::unordered_map<uint16_t, uint64_t> version_counts;
    std::unordered_map<uint16_t, uint64_t> cipher_suite_counts;
    std::unordered_map<std::string, uint64_t> sni_counts;
    
    void record_connection(bool success) {
        total_connections++;
        if (success) {
            successful_handshakes++;
        } else {
            failed_handshakes++;
        }
        last_activity = std::chrono::steady_clock::now();
    }
    
    void record_handshake_time(std::chrono::milliseconds duration) {
        // 简单的移动平均
        avg_handshake_time = (avg_handshake_time + duration) / 2;
    }
    
    [[nodiscard]] double get_success_rate() const {
        return total_connections > 0 ? 
            static_cast<double>(successful_handshakes) / total_connections : 0.0;
    }
};

// 主要的TLS解析信息结构
struct TLSInfo {
    TLSVersion version = TLSVersion::TLS1_2;
    TLSRecordType record_type = TLSRecordType::HANDSHAKE;
    uint16_t record_length = 0;
    
    // 握手信息
    TLSHandshakeType handshake_type = TLSHandshakeType::CLIENT_HELLO;
    uint32_t handshake_length = 0;
    std::vector<TLSExtension> extensions;
    std::vector<TLSCipherSuite> cipher_suites;
    std::vector<uint8_t> compression_methods;
    std::array<uint8_t, 32> client_random{};
    std::array<uint8_t, 32> server_random{};
    std::vector<uint8_t> session_id;
    
    // 证书链
    std::vector<TLSCertificate> certificate_chain;
    TLSCertificate server_certificate;
    TLSCertificate client_certificate;
    
    // 会话管理
    TLSSession session;
    TLSHandshakeState handshake_state;
    
    // 警告和错误
    uint8_t alert_level = 0;
    uint8_t alert_description = 0;
    std::string alert_message;
    
    // 应用数据
    uint32_t application_data_length = 0;
    bool is_encrypted = false;
    std::vector<uint8_t> decrypted_data;
    
    // 连接信息
    std::string server_name;  // SNI
    std::vector<std::string> alpn_protocols;
    std::string selected_alpn;
    uint16_t server_port = 443;
    std::string client_ip;
    std::string server_ip;
    
    // 统计和性能
    TLSStatistics statistics;
    
    // 安全分析
    TLSSecurityAnalysis security_analysis;
    
    // 原始数据（用于深度分析）
    std::vector<uint8_t> raw_handshake_data;
    std::vector<uint8_t> raw_application_data;
    
    // 元数据
    bool is_valid = false;
    std::string error_message;
    std::chrono::steady_clock::time_point parse_timestamp;
    uint32_t flow_id = 0;
    
    [[nodiscard]] bool is_handshake_complete() const {
        return handshake_state.is_complete();
    }
    
    [[nodiscard]] bool is_secure_configuration() const {
        return security_analysis.security_score >= 80 && 
               security_analysis.is_secure;
    }
    
    [[nodiscard]] std::string get_security_summary() const {
        return "TLS " + std::to_string(static_cast<uint16_t>(version)) + 
               " - Score: " + std::to_string(security_analysis.security_score) + 
               " - Grade: " + security_analysis.security_grade;
    }
};

// TLS深度解析器类
class TLSDeepInspector {
public:
    TLSDeepInspector();
    ~TLSDeepInspector() = default;

    // 主要解析方法
    bool parse_tls_packet(const protocol_parser::core::BufferView& buffer, TLSInfo& tls_info);
    
    // 深度分析
    TLSSecurityAnalysis analyze_security(const TLSInfo& info) const;
    std::vector<std::string> detect_vulnerabilities(const TLSInfo& info) const;
    uint32_t calculate_security_score(const TLSInfo& info) const;
    std::string determine_security_grade(uint32_t score) const;
    
    // 证书分析
    bool analyze_certificate_chain(const std::vector<TLSCertificate>& chain, TLSSecurityAnalysis& analysis) const;
    bool validate_certificate(const TLSCertificate& cert) const;
    
    // 协议检测
    bool can_parse(const protocol_parser::core::BufferView& buffer) const;
    TLSVersion detect_tls_version(const protocol_parser::core::BufferView& buffer) const;
    
    // 配置和管理
    void set_deep_inspection_enabled(bool enabled) { deep_inspection_enabled_ = enabled; }
    void set_certificate_validation_enabled(bool enabled) { certificate_validation_enabled_ = enabled; }
    void set_vulnerability_scanning_enabled(bool enabled) { vulnerability_scanning_enabled_ = enabled; }
    void enable_advanced_analytics(bool enabled) { advanced_analytics_enabled_ = enabled; }
    
    // 统计和报告
    TLSStatistics get_global_statistics() const { return global_stats_; }
    void reset_statistics() { global_stats_ = TLSStatistics{}; }
    std::string generate_security_report() const;

private:
    bool deep_inspection_enabled_ = true;
    bool certificate_validation_enabled_ = true;
    bool vulnerability_scanning_enabled_ = true;
    bool advanced_analytics_enabled_ = true;
    
    TLSStatistics global_stats_;
    
    // 密码套件数据库
    std::unordered_map<uint16_t, TLSCipherSuite> cipher_suite_database_;
    
    // 内部解析方法
    bool parse_tls_record(const protocol_parser::core::BufferView& buffer, TLSInfo& info);
    bool parse_handshake_message(const protocol_parser::core::BufferView& buffer, TLSInfo& info);
    bool parse_client_hello(const protocol_parser::core::BufferView& buffer, TLSInfo& info);
    bool parse_server_hello(const protocol_parser::core::BufferView& buffer, TLSInfo& info);
    bool parse_certificate_message(const protocol_parser::core::BufferView& buffer, TLSInfo& info);
    bool parse_extensions(const protocol_parser::core::BufferView& buffer, std::vector<TLSExtension>& extensions);
    
    // 漏洞检测方法
    bool check_heartbleed_vulnerability(const TLSInfo& info) const;
    bool check_poodle_vulnerability(const TLSInfo& info) const;
    bool check_beast_vulnerability(const TLSInfo& info) const;
    bool check_crime_vulnerability(const TLSInfo& info) const;
    bool check_freak_vulnerability(const TLSInfo& info) const;
    bool check_logjam_vulnerability(const TLSInfo& info) const;
    
    // 工具方法
    void initialize_cipher_suite_database();
    bool is_weak_cipher_suite(const TLSCipherSuite& suite) const;
    bool is_deprecated_protocol(TLSVersion version) const;
    bool supports_perfect_forward_secrecy(const TLSCipherSuite& suite) const;
    std::string get_vulnerability_description(const std::string& vuln_name) const;
    
    // 常量
    static constexpr uint16_t TLS_RECORD_HEADER_SIZE = 5;
    static constexpr uint16_t TLS_HANDSHAKE_HEADER_SIZE = 4;
    static constexpr uint16_t MAX_TLS_RECORD_SIZE = 16384 + 2048;
    static constexpr uint16_t TLS_DEFAULT_PORT = 443;
};

} // namespace protocol_parser::security