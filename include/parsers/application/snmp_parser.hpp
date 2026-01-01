#pragma once

#include "parsers/base_parser.hpp"
#include "../base_parser.hpp"
#include <vector>
#include <string>
#include <optional>
#include <variant>
#include <unordered_map>
#include <memory>

namespace protocol_parser::parsers {

// SNMP版本定义
enum class SNMPVersion : uint32_t {
    VERSION_1 = 0,    // SNMPv1
    VERSION_2C = 1,   // SNMPv2c  
    VERSION_3 = 3     // SNMPv3
};

// SNMP PDU类型 (RFC 1157, 3416)
enum class SNMPPDUType : uint8_t {
    GET_REQUEST = 0x00,
    GET_NEXT_REQUEST = 0x01, 
    GET_RESPONSE = 0x02,
    SET_REQUEST = 0x03,
    TRAP = 0x04,
    GET_BULK_REQUEST = 0x05,
    INFORM_REQUEST = 0x06,
    TRAP_V2 = 0x07,
    REPORT = 0x08
};

// SNMP错误状态 (RFC 1157)
enum class SNMPErrorStatus : uint32_t {
    NO_ERROR = 0,
    TOO_BIG = 1,
    NO_SUCH_NAME = 2,
    BAD_VALUE = 3,
    READ_ONLY = 4,
    GEN_ERR = 5,
    NO_ACCESS = 6,
    WRONG_TYPE = 7,
    WRONG_LENGTH = 8,
    WRONG_ENCODING = 9,
    WRONG_VALUE = 10,
    NO_CREATION = 11,
    INCONSISTENT_VALUE = 12,
    RESOURCE_UNAVAILABLE = 13,
    COMMIT_FAILED = 14,
    UNDO_FAILED = 15,
    AUTHORIZATION_ERROR = 16,
    NOT_WRITABLE = 17,
    INCONSISTENT_NAME = 18
};

// BER编码类型
enum class BERType : uint8_t {
    INTEGER = 0x02,
    OCTET_STRING = 0x04,
    NULL_TYPE = 0x05,
    OBJECT_IDENTIFIER = 0x06,
    SEQUENCE = 0x30,
    IPADDRESS = 0x40,
    COUNTER32 = 0x41,
    GAUGE32 = 0x42,
    TIMETICKS = 0x43,
    OPAQUE = 0x44,
    COUNTER64 = 0x46
};

// OID (Object Identifier) 表示
class OID {
public:
    OID() = default;
    explicit OID(const std::vector<uint32_t>& components);
    explicit OID(const std::string& dotted_notation);
    
    [[nodiscard]] const std::vector<uint32_t>& components() const noexcept;
    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] bool is_prefix_of(const OID& other) const noexcept;
    
    bool operator==(const OID& other) const noexcept;
    bool operator<(const OID& other) const noexcept;
    
private:
    std::vector<uint32_t> components_;
};

// SNMP值类型的变体
using SNMPValue = std::variant<
    int64_t,                    // INTEGER
    std::string,                // OCTET_STRING
    std::monostate,             // NULL
    OID,                        // OBJECT_IDENTIFIER
    uint32_t,                   // IPADDRESS (as uint32)
    uint32_t,                   // COUNTER32
    uint32_t,                   // GAUGE32
    uint32_t,                   // TIMETICKS
    std::vector<uint8_t>,       // OPAQUE
    uint64_t                    // COUNTER64
>;

// 变量绑定 (Variable Binding)
struct VarBind {
    OID oid;
    BERType type{BERType::NULL_TYPE};
    SNMPValue value;
    
    [[nodiscard]] std::string value_to_string() const;
    [[nodiscard]] bool is_null() const noexcept;
    [[nodiscard]] bool is_exception() const noexcept;
};

// SNMP PDU结构
struct SNMPPDU {
    SNMPPDUType type{SNMPPDUType::GET_REQUEST};
    uint32_t request_id{0};
    SNMPErrorStatus error_status{SNMPErrorStatus::NO_ERROR};
    uint32_t error_index{0};
    std::vector<VarBind> variable_bindings;
    
    // 特殊字段（用于某些PDU类型）
    uint32_t non_repeaters{0};      // GetBulk
    uint32_t max_repetitions{0};    // GetBulk
    uint32_t enterprise{0};         // Trap v1
    uint32_t agent_addr{0};         // Trap v1  
    uint32_t generic_trap{0};       // Trap v1
    uint32_t specific_trap{0};      // Trap v1
    uint32_t timestamp{0};          // Trap v1
};

// SNMPv3 安全模型
enum class SNMPv3SecurityModel : uint32_t {
    ANY = 0,
    SNMPv1 = 1,
    SNMPv2c = 2,
    USM = 3     // User-based Security Model
};

// SNMPv3 安全级别
enum class SNMPv3SecurityLevel : uint8_t {
    NO_AUTH_NO_PRIV = 0,    // noAuthNoPriv
    AUTH_NO_PRIV = 1,       // authNoPriv  
    AUTH_PRIV = 3           // authPriv
};

// SNMPv3 消息标志
struct SNMPv3MessageFlags {
    bool authentication{false};
    bool privacy{false};
    bool reportable{false};
};

// SNMPv3 消息头
struct SNMPv3MessageHeader {
    uint32_t message_id{0};
    uint32_t message_max_size{0};
    SNMPv3MessageFlags message_flags;
    SNMPv3SecurityModel security_model{SNMPv3SecurityModel::USM};
};

// SNMPv3 安全参数 (USM)
struct SNMPv3SecurityParameters {
    std::string authoritative_engine_id;
    uint32_t authoritative_engine_boots{0};
    uint32_t authoritative_engine_time{0};
    std::string user_name;
    std::string auth_parameters;
    std::string priv_parameters;
};

// SNMPv3 作用域PDU
struct SNMPv3ScopedPDU {
    std::string context_engine_id;
    std::string context_name;
    SNMPPDU pdu;
};

// 完整的SNMP消息
struct SNMPMessage {
    SNMPVersion version{SNMPVersion::VERSION_1};
    
    // v1/v2c 字段
    std::string community;
    
    // v3 字段
    std::optional<SNMPv3MessageHeader> v3_header;
    std::optional<SNMPv3SecurityParameters> v3_security_params;
    std::optional<SNMPv3ScopedPDU> v3_scoped_pdu;
    
    // 通用PDU (对于v1/v2c直接包含，对于v3在scoped_pdu中)
    SNMPPDU pdu;
    
    [[nodiscard]] bool is_v3() const noexcept;
    [[nodiscard]] bool is_encrypted() const noexcept;
    [[nodiscard]] bool is_authenticated() const noexcept;
    [[nodiscard]] const SNMPPDU& get_pdu() const noexcept;
};

class SNMPParser : public BaseParser {
public:
    explicit SNMPParser() = default;
    ~SNMPParser() override = default;

    // 基类接口实现
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    // SNMP特定接口
    [[nodiscard]] std::string get_protocol_name() const noexcept;
    [[nodiscard]] uint16_t get_default_port() const noexcept;
    [[nodiscard]] std::vector<uint16_t> get_supported_ports() const noexcept;
    [[nodiscard]] const SNMPMessage& get_snmp_message() const noexcept;
    [[nodiscard]] bool is_snmp_packet() const noexcept;
    
    // 验证和安全检查
    [[nodiscard]] bool validate_message() const noexcept;
    [[nodiscard]] bool is_malformed() const noexcept;
    
    // 高级分析功能
    struct SNMPAnalysis {
        bool is_request{false};
        bool is_response{false};
        bool is_trap{false};
        bool is_bulk_request{false};
        bool has_errors{false};
        bool is_encrypted{false};
        bool is_authenticated{false};
        size_t variable_count{0};
        size_t oid_complexity{0};           // OID复杂度分析
        std::vector<std::string> mib_modules; // 检测到的MIB模块
        std::vector<std::string> security_issues;
        double parse_complexity{0.0};      // 解析复杂度
    };
    
    [[nodiscard]] SNMPAnalysis analyze_message() const noexcept;
    
    // MIB相关功能
    struct MIBInfo {
        std::string module_name;
        std::string object_name;
        std::string description;
        BERType syntax;
        bool is_table{false};
        bool is_readable{false};
        bool is_writable{false};
    };
    
    [[nodiscard]] std::optional<MIBInfo> lookup_oid(const OID& oid) const noexcept;
    void load_mib_database(const std::string& mib_file_path);
    
    // 统计信息
    struct SNMPStatistics {
        uint64_t total_messages{0};
        uint64_t v1_messages{0};
        uint64_t v2c_messages{0};
        uint64_t v3_messages{0};
        uint64_t get_requests{0};
        uint64_t get_responses{0};
        uint64_t set_requests{0};
        uint64_t traps{0};
        uint64_t bulk_requests{0};
        uint64_t malformed_messages{0};
        uint64_t authentication_failures{0};
        uint64_t authorization_failures{0};
        std::unordered_map<std::string, uint64_t> community_usage;
        std::unordered_map<std::string, uint64_t> oid_access_count;
        std::unordered_map<SNMPErrorStatus, uint64_t> error_distribution;
    };
    
    [[nodiscard]] const SNMPStatistics& get_statistics() const noexcept;
    void reset_statistics() noexcept;

    // 工具方法
    [[nodiscard]] static std::string pdu_type_to_string(SNMPPDUType type) noexcept;
    [[nodiscard]] static std::string error_status_to_string(SNMPErrorStatus status) noexcept;
    [[nodiscard]] static std::string version_to_string(SNMPVersion version) noexcept;
    [[nodiscard]] static std::string ber_type_to_string(BERType type) noexcept;
    [[nodiscard]] static bool is_valid_community(const std::string& community) noexcept;
    [[nodiscard]] static uint32_t ip_string_to_uint32(const std::string& ip) noexcept;

private:
    SNMPMessage snmp_message_;
    bool parsed_successfully_{false};
    bool is_malformed_{false};
    SNMPStatistics statistics_;
    
    // MIB数据库
    std::unordered_map<std::string, MIBInfo> mib_database_;
    
    // 私有解析方法
    [[nodiscard]] bool parse_ber_sequence(const uint8_t* data, size_t size, size_t& offset) noexcept;
    [[nodiscard]] bool parse_ber_length(const uint8_t* data, size_t size, size_t& offset, size_t& length) noexcept;
    [[nodiscard]] bool parse_ber_integer(const uint8_t* data, size_t size, size_t& offset, int64_t& value) noexcept;
    [[nodiscard]] bool parse_ber_octet_string(const uint8_t* data, size_t size, size_t& offset, std::string& value) noexcept;
    [[nodiscard]] bool parse_ber_oid(const uint8_t* data, size_t size, size_t& offset, OID& oid) noexcept;
    [[nodiscard]] bool parse_snmp_value(const uint8_t* data, size_t size, size_t& offset, BERType type, SNMPValue& value) noexcept;
    
    [[nodiscard]] bool parse_v1_v2c_message(const uint8_t* data, size_t size, size_t& offset) noexcept;
    [[nodiscard]] bool parse_v3_message(const uint8_t* data, size_t size, size_t& offset) noexcept;
    [[nodiscard]] bool parse_pdu(const uint8_t* data, size_t size, size_t& offset, SNMPPDU& pdu) noexcept;
    [[nodiscard]] bool parse_variable_bindings(const uint8_t* data, size_t size, size_t& offset, std::vector<VarBind>& bindings) noexcept;
    
    // 验证方法
    [[nodiscard]] bool validate_ber_encoding(const uint8_t* data, size_t size) const noexcept;
    [[nodiscard]] bool validate_oid(const OID& oid) const noexcept;
    [[nodiscard]] bool validate_pdu(const SNMPPDU& pdu) const noexcept;
    
    // 安全检查
    void perform_security_analysis() noexcept;
    [[nodiscard]] bool detect_dos_patterns() const noexcept;
    [[nodiscard]] bool validate_message_size() const noexcept;
    
    // 统计更新
    void update_statistics(const SNMPMessage& message) noexcept;
    
    // MIB处理
    void initialize_standard_mibs() noexcept;
    [[nodiscard]] std::string classify_oid_by_prefix(const OID& oid) const noexcept;
    
    // 常量定义
    static constexpr size_t MAX_MESSAGE_SIZE = 65507;    // RFC 3411
    static constexpr size_t MAX_OID_LENGTH = 128;        // 实际限制
    static constexpr size_t MAX_VARBIND_COUNT = 2147483647; // RFC限制
    static constexpr uint16_t SNMP_DEFAULT_PORT = 161;   // SNMP Agent端口
    static constexpr uint16_t SNMP_TRAP_PORT = 162;      // SNMP Trap端口
};

} // namespace protocol_parser::parsers