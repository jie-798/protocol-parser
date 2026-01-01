#pragma once

#include "../base_parser.hpp"
#include <vector>
#include <string>
#include <optional>
#include <variant>
#include <unordered_map>
#include <memory>

// 简化类型别名
using BufferView = protocol_parser::core::BufferView;
using ParseResult = protocol_parser::parsers::ParseResult;
using BaseParser = protocol_parser::parsers::BaseParser;
using ProtocolInfo = protocol_parser::parsers::ProtocolInfo;
using ParseContext = protocol_parser::parsers::ParseContext;

namespace protocol_parser::parsers {

// MQTT版本定义 (RFC 3.1.1, MQTT 5.0)
enum class MQTTVersion : uint8_t {
    MQTT_3_1 = 3,     // MQTT v3.1
    MQTT_3_1_1 = 4,   // MQTT v3.1.1 (最常用)
    MQTT_5_0 = 5      // MQTT v5.0 (最新版)
};

// MQTT消息类型 (RFC 3.1.1 Section 2.2.1)
enum class MQTTMessageType : uint8_t {
    RESERVED_0 = 0,    // 保留
    CONNECT = 1,       // 客户端连接请求
    CONNACK = 2,       // 连接确认
    PUBLISH = 3,       // 发布消息
    PUBACK = 4,        // 发布确认 (QoS 1)
    PUBREC = 5,        // 发布收到 (QoS 2)
    PUBREL = 6,        // 发布释放 (QoS 2)
    PUBCOMP = 7,       // 发布完成 (QoS 2)
    SUBSCRIBE = 8,     // 订阅请求
    SUBACK = 9,        // 订阅确认
    UNSUBSCRIBE = 10,  // 取消订阅
    UNSUBACK = 11,     // 取消订阅确认
    PINGREQ = 12,      // 心跳请求
    PINGRESP = 13,     // 心跳响应
    DISCONNECT = 14,   // 断开连接
    AUTH = 15          // 认证交换 (MQTT 5.0)
};

// MQTT QoS等级
enum class MQTTQoS : uint8_t {
    AT_MOST_ONCE = 0,   // 最多一次
    AT_LEAST_ONCE = 1,  // 至少一次
    EXACTLY_ONCE = 2,   // 只有一次
    RESERVED = 3        // 保留
};

// MQTT连接返回码 (MQTT 3.1.1)
enum class MQTTConnectReturnCode : uint8_t {
    CONNECTION_ACCEPTED = 0,                    // 连接已接受
    UNACCEPTABLE_PROTOCOL_VERSION = 1,         // 不可接受的协议版本
    IDENTIFIER_REJECTED = 2,                   // 标识符被拒绝
    SERVER_UNAVAILABLE = 3,                    // 服务器不可用
    BAD_USERNAME_OR_PASSWORD = 4,              // 用户名或密码错误
    NOT_AUTHORIZED = 5                         // 未授权
};

// MQTT 5.0属性类型
enum class MQTTPropertyType : uint8_t {
    PAYLOAD_FORMAT_INDICATOR = 0x01,
    MESSAGE_EXPIRY_INTERVAL = 0x02,
    CONTENT_TYPE = 0x03,
    RESPONSE_TOPIC = 0x08,
    CORRELATION_DATA = 0x09,
    SUBSCRIPTION_IDENTIFIER = 0x0B,
    SESSION_EXPIRY_INTERVAL = 0x11,
    ASSIGNED_CLIENT_IDENTIFIER = 0x12,
    SERVER_KEEP_ALIVE = 0x13,
    AUTHENTICATION_METHOD = 0x15,
    AUTHENTICATION_DATA = 0x16,
    REQUEST_PROBLEM_INFORMATION = 0x17,
    WILL_DELAY_INTERVAL = 0x18,
    REQUEST_RESPONSE_INFORMATION = 0x19,
    RESPONSE_INFORMATION = 0x1A,
    SERVER_REFERENCE = 0x1C,
    REASON_STRING = 0x1F,
    RECEIVE_MAXIMUM = 0x21,
    TOPIC_ALIAS_MAXIMUM = 0x22,
    TOPIC_ALIAS = 0x23,
    MAXIMUM_QOS = 0x24,
    RETAIN_AVAILABLE = 0x25,
    USER_PROPERTY = 0x26,
    MAXIMUM_PACKET_SIZE = 0x27,
    WILDCARD_SUBSCRIPTION_AVAILABLE = 0x28,
    SUBSCRIPTION_IDENTIFIER_AVAILABLE = 0x29,
    SHARED_SUBSCRIPTION_AVAILABLE = 0x2A
};

// MQTT属性值类型
using MQTTPropertyValue = std::variant<
    uint8_t,                    // Byte
    uint16_t,                   // Two Byte Integer
    uint32_t,                   // Four Byte Integer
    std::string,                // UTF-8 String
    std::vector<uint8_t>,       // Binary Data
    std::pair<std::string, std::string>  // UTF-8 String Pair (User Property)
>;

// MQTT属性
struct MQTTProperty {
    MQTTPropertyType type;
    MQTTPropertyValue value;

    [[nodiscard]] std::string value_to_string() const;
    [[nodiscard]] size_t get_size() const noexcept;
};

// MQTT固定头部
struct MQTTFixedHeader {
    MQTTMessageType message_type{MQTTMessageType::RESERVED_0};
    bool dup_flag{false};          // 重复标志
    MQTTQoS qos_level{MQTTQoS::AT_MOST_ONCE};
    bool retain_flag{false};       // 保留标志
    uint32_t remaining_length{0};  // 剩余长度

    static constexpr size_t MIN_SIZE = 2;
    static constexpr size_t MAX_SIZE = 5;  // 1字节控制+4字节长度

    [[nodiscard]] size_t get_header_size() const noexcept;
    [[nodiscard]] bool is_valid() const noexcept;
};

// MQTT CONNECT消息
struct MQTTConnectMessage {
    std::string protocol_name{"MQTT"};
    MQTTVersion protocol_version{MQTTVersion::MQTT_3_1_1};

    // 连接标志
    bool clean_session{true};      // 清除会话 (3.1.1) / clean_start (5.0)
    bool will_flag{false};         // 遗嘱标志
    MQTTQoS will_qos{MQTTQoS::AT_MOST_ONCE};
    bool will_retain{false};       // 遗嘱保留
    bool password_flag{false};     // 密码标志
    bool username_flag{false};     // 用户名标志

    uint16_t keep_alive{60};       // 保活时间（秒）

    // 属性 (MQTT 5.0)
    std::vector<MQTTProperty> properties;

    // 载荷
    std::string client_id;
    std::string will_topic;
    std::string will_message;
    std::string username;
    std::string password;

    [[nodiscard]] bool validate() const noexcept;
};

// MQTT CONNACK消息
struct MQTTConnackMessage {
    bool session_present{false};   // 会话存在标志
    MQTTConnectReturnCode return_code{MQTTConnectReturnCode::CONNECTION_ACCEPTED};

    // MQTT 5.0属性
    std::vector<MQTTProperty> properties;

    [[nodiscard]] bool is_success() const noexcept {
        return return_code == MQTTConnectReturnCode::CONNECTION_ACCEPTED;
    }
};

// MQTT PUBLISH消息
struct MQTTPublishMessage {
    std::string topic;
    uint16_t packet_id{0};         // QoS > 0时需要
    std::vector<MQTTProperty> properties;  // MQTT 5.0
    std::vector<uint8_t> payload;

    [[nodiscard]] bool validate() const noexcept;
    [[nodiscard]] std::string payload_as_string() const;
};

// MQTT SUBSCRIBE消息
struct MQTTSubscribeMessage {
    uint16_t packet_id{0};
    std::vector<MQTTProperty> properties;  // MQTT 5.0

    struct TopicFilter {
        std::string topic;
        MQTTQoS max_qos{MQTTQoS::AT_MOST_ONCE};
        bool no_local{false};      // MQTT 5.0
        bool retain_as_published{false};  // MQTT 5.0
        uint8_t retain_handling{0};  // MQTT 5.0
    };

    std::vector<TopicFilter> topic_filters;

    [[nodiscard]] bool validate() const noexcept;
};

// MQTT消息联合体
using MQTTMessage = std::variant<
    std::monostate,              // 空状态
    MQTTConnectMessage,
    MQTTConnackMessage,
    MQTTPublishMessage,
    MQTTSubscribeMessage
>;

// MQTT数据包结构
struct MQTTPacket {
    MQTTFixedHeader fixed_header;
    MQTTMessage message;

    [[nodiscard]] bool is_valid() const noexcept;
    [[nodiscard]] size_t get_total_size() const noexcept;
    [[nodiscard]] MQTTMessageType get_message_type() const noexcept {
        return fixed_header.message_type;
    }
};

// MQTT解析器
class MQTTParser : public BaseParser {
public:
    explicit MQTTParser() = default;
    ~MQTTParser() override = default;

    // 基类接口实现
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    // MQTT特定方法
    [[nodiscard]] std::string get_protocol_name() const noexcept;
    [[nodiscard]] uint16_t get_default_port() const noexcept;
    [[nodiscard]] std::vector<uint16_t> get_supported_ports() const noexcept;

    // MQTT解析结果访问
    [[nodiscard]] const MQTTPacket& get_mqtt_packet() const noexcept;
    [[nodiscard]] bool is_mqtt_packet() const noexcept;

    // 验证和安全检查
    [[nodiscard]] bool validate_packet() const noexcept;
    [[nodiscard]] bool is_malformed() const noexcept;

    // 高级分析功能
    struct MQTTAnalysis {
        bool is_client_message{false};
        bool is_server_message{false};
        bool is_control_message{false};
        bool is_data_message{false};
        bool has_payload{false};
        bool uses_authentication{false};
        bool has_will_message{false};
        MQTTVersion detected_version{MQTTVersion::MQTT_3_1_1};
        std::optional<std::string> client_id;
        std::optional<std::string> topic;
        size_t payload_size{0};
        std::vector<std::string> topics;  // 订阅的主题
        bool has_security_issues{false};
        std::vector<std::string> security_warnings;
    };

    [[nodiscard]] MQTTAnalysis analyze_packet() const noexcept;

    // 统计信息
    struct MQTTStatistics {
        uint64_t total_packets{0};
        uint64_t connect_count{0};
        uint64_t connack_count{0};
        uint64_t publish_count{0};
        uint64_t subscribe_count{0};
        uint64_t unsubscribe_count{0};
        uint64_t pingreq_count{0};
        uint64_t pingresp_count{0};
        uint64_t disconnect_count{0};
        uint64_t malformed_count{0};
        uint64_t v3_1_count{0};
        uint64_t v3_1_1_count{0};
        uint64_t v5_0_count{0};
        std::unordered_map<std::string, uint64_t> topic_usage;
        std::unordered_map<std::string, uint64_t> client_usage;
    };

    [[nodiscard]] const MQTTStatistics& get_statistics() const noexcept;
    void reset_statistics() noexcept;

    // 工具方法
    [[nodiscard]] static std::string message_type_to_string(MQTTMessageType type) noexcept;
    [[nodiscard]] static std::string version_to_string(MQTTVersion version) noexcept;
    [[nodiscard]] static std::string qos_to_string(MQTTQoS qos) noexcept;
    [[nodiscard]] static std::string return_code_to_string(MQTTConnectReturnCode code) noexcept;
    [[nodiscard]] static bool is_valid_topic(const std::string& topic) noexcept;
    [[nodiscard]] static bool is_wildcard_topic(const std::string& topic) noexcept;

    // 公开常量
    static constexpr uint16_t MQTT_DEFAULT_PORT = 1883;     // 标准MQTT端口
    static constexpr uint16_t MQTT_TLS_PORT = 8883;         // MQTT over TLS端口
    static constexpr uint16_t MQTT_WS_PORT = 80;            // MQTT over WebSocket端口
    static constexpr uint16_t MQTT_WSS_PORT = 443;          // MQTT over WSS端口
    static constexpr size_t MAX_PACKET_SIZE = 268435455;    // 最大包大小 (256MB - 1)
    static constexpr size_t MAX_TOPIC_LENGTH = 65535;       // 最大主题长度
    static constexpr size_t MAX_CLIENT_ID_LENGTH = 23;      // 推荐客户端ID长度

private:
    MQTTPacket mqtt_packet_;
    bool parsed_successfully_{false};
    bool is_malformed_{false};
    MQTTStatistics statistics_;

    // 私有解析方法
    [[nodiscard]] ParseResult parse_fixed_header(const uint8_t* data, size_t size, size_t& offset) noexcept;
    [[nodiscard]] ParseResult parse_variable_header(const uint8_t* data, size_t size, size_t& offset) noexcept;
    [[nodiscard]] ParseResult parse_payload(const uint8_t* data, size_t size, size_t& offset) noexcept;

    // 消息解析方法
    [[nodiscard]] ParseResult parse_connect_message(const uint8_t* data, size_t size, size_t& offset) noexcept;
    [[nodiscard]] ParseResult parse_connack_message(const uint8_t* data, size_t size, size_t& offset) noexcept;
    [[nodiscard]] ParseResult parse_publish_message(const uint8_t* data, size_t size, size_t& offset) noexcept;
    [[nodiscard]] ParseResult parse_subscribe_message(const uint8_t* data, size_t size, size_t& offset) noexcept;

    // 工具方法
    [[nodiscard]] uint32_t decode_remaining_length(const uint8_t* data, size_t size, size_t& offset) noexcept;
    [[nodiscard]] std::string read_utf8_string(const uint8_t* data, size_t size, size_t& offset) noexcept;
    [[nodiscard]] ParseResult parse_properties(const uint8_t* data, size_t size, size_t& offset,
                                              std::vector<MQTTProperty>& properties) noexcept;

    // 验证方法
    [[nodiscard]] bool validate_fixed_header() const noexcept;
    [[nodiscard]] bool validate_topic_name(const std::string& topic) const noexcept;
    [[nodiscard]] bool validate_client_id(const std::string& client_id) const noexcept;

    // 安全检查
    void perform_security_analysis() noexcept;

    // 统计更新
    void update_statistics(const MQTTPacket& packet) noexcept;
};

} // namespace protocol_parser::parsers
