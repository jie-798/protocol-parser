#pragma once

#include "../../parsers/base_parser.hpp"
#include "../../core/buffer_view.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <chrono>

namespace protocol_parser::signaling {

// 使用父命名空间的类型
using protocol_parser::parsers::ProtocolInfo;
using protocol_parser::parsers::ParseResult;
using protocol_parser::parsers::ParseContext;
using protocol_parser::core::BufferView;

// Diameter命令代码 (RFC 6733)
enum class DiameterCommandCode : uint32_t {
    // 设备相关
    CapabilitiesExchange = 257,
    DeviceWatchdog = 280,
    DisconnectPeer = 282,

    // 认证授权
    AA = 265,                      // Authentication Authorization
    AuthApplication = 265,
    AbortSession = 274,
    SessionTermination = 275,
    ReAuth = 278,
    Accounting = 271,

    // 基于EAP
    EAP = 268,

    // 用户相关
    UserData = 306
};

// Diameter应用ID
enum class DiameterApplicationId : uint32_t {
    Common = 0,
    NAS = 1,
    MobileIP = 2,
    DiameterBaseAccounting = 3,
    CreditControl = 4,
    EAP = 5,
    SIP = 6,
    MobileIPv4 = 7,
    DiameterCMS = 10,
    DiameterEKA = 11,
    GQ = 13,
    S13 = 15,
    SLg = 17,
    RX = 16777217,
    Gx = 16777218,
    Cx = 16777219,
    Dx = 16777220,
    Sh = 16777221,
    Dh = 16777223
};

// Diameter AVP类型
enum class DiameterAVPType : uint32_t {
    // 通用AVP
    UserName = 1,
    UserPassword = 2,
    DestinationHost = 293,
    DestinationRealm = 283,
    AuthApplicationId = 258,
    AcctApplicationId = 259,
    VendorId = 266,
    VendorSpecificApplicationId = 260,
    RedirectHost = 272,
    DisconnectCause = 273,
    AuthSessionState = 277,
    OriginHost = 264,
    OriginRealm = 296,
    OriginStateId = 278,
    SessionId = 263,
    SessionTimeout = 27,
    AuthRequestType = 274,
    AuthLifetime = 276,

    // 结果相关
    ResultCode = 268,
    ExperimentalResultCode = 501,
    ErrorMessage = 281,
    ErrorReportingHost = 274,

    // NAS相关
    NASIPAddress = 4,
    NASIPv6Address = 95,
    NASIdentifier = 32,
    NASPort = 5,
    NASPortType = 61,

    // 用户相关
    FramedIPAddress = 8,
    FramedIPv6Prefix = 97,
    FramedInterfaceId = 96,
    FramedIPNetmask = 9,

    // QoS相关
    QoSFilter = 442,

    // 移动性
    MNHA = 332,
    VisitedNetworkIdentifier = 600,

    // 计费相关
    AcctMultiSessionId = 50,
    AcctSessionId = 44,
    AcctStatusType = 45
};

// Diameter AVP数据类型
enum class DiameterAVPDataType : uint8_t {
    OctetString = 1,
    Integer32 = 2,
    Integer64 = 3,
    Unsigned32 = 4,
    Unsigned64 = 5,
    Float32 = 6,
    Float64 = 7,
    Grouped = 8
};

// Diameter AVP标志位
struct DiameterAVPFlags {
    bool vendor_specific = false;
    bool mandatory = false;
    bool is_private_flag = false;  // renamed from 'private' (reserved keyword)

    [[nodiscard]] uint8_t to_uint8() const;
    static DiameterAVPFlags from_uint8(uint8_t flags);
};

// Diameter AVP
struct DiameterAVP {
    uint32_t code = 0;
    DiameterAVPFlags flags;
    uint32_t vendor_id = 0;
    uint32_t length = 0;
    std::vector<uint8_t> data;

    [[nodiscard]] bool is_mandatory() const { return flags.mandatory; }
    [[nodiscard]] bool is_vendor_specific() const { return flags.vendor_specific; }

    [[nodiscard]] std::string to_string() const;
    [[nodiscard]] std::string get_value_string() const;
};

// Diameter头部
struct DiameterHeader {
    uint8_t version = 1;
    uint32_t message_length = 0;
    uint8_t flags = 0;  // Diameter消息标志位
    uint32_t command_code = 0;
    uint32_t application_id = 0;
    uint32_t hop_by_hop_id = 0;
    uint32_t end_to_end_id = 0;

    [[nodiscard]] bool is_request() const { return (flags & 0x80) == 0; }
    [[nodiscard]] bool is_proxiable() const { return (flags & 0x40) != 0; }
    [[nodiscard]] bool is_error() const { return (flags & 0x20) != 0; }
    [[nodiscard]] bool is_retransmit() const { return (flags & 0x10) != 0; }

    [[nodiscard]] std::string to_string() const;
};

// Diameter消息
struct DiameterMessage {
    DiameterHeader header;
    std::vector<DiameterAVP> avps;

    // 解析后的关键字段
    std::optional<std::string> session_id;
    std::optional<std::string> origin_host;
    std::optional<std::string> origin_realm;
    std::optional<std::string> destination_host;
    std::optional<std::string> destination_realm;
    std::optional<std::string> user_name;
    std::optional<uint32_t> result_code;
    std::optional<std::string> error_message;
    std::optional<uint32_t> auth_application_id;
    std::optional<uint64_t> origin_state_id;

    // 元数据
    bool is_error = false;
    std::string error_description;
    std::chrono::steady_clock::time_point parse_timestamp;

    [[nodiscard]] std::string get_command_name() const;
    [[nodiscard]] std::string get_application_name() const;
    [[nodiscard]] std::string to_string() const;
};

// Diameter解析器
class DiameterParser : public protocol_parser::parsers::BaseParser {
public:
    DiameterParser() = default;
    ~DiameterParser() override = default;

    // BaseParser接口实现
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    // Diameter特定接口
    [[nodiscard]] bool parse_diameter_message(const BufferView& buffer, DiameterMessage& msg);
    [[nodiscard]] DiameterMessage parse_message(const BufferView& buffer);

    // AVP解析
    [[nodiscard]] bool parse_avp(const BufferView& buffer, DiameterAVP& avp);
    [[nodiscard]] bool parse_grouped_avp(const BufferView& buffer, std::vector<DiameterAVP>& avps);

    // 工具方法
    [[nodiscard]] static std::string get_command_name(uint32_t cmd);
    [[nodiscard]] static std::string get_application_name(uint32_t app_id);
    [[nodiscard]] static std::string get_avp_name(uint32_t avp_code);
    [[nodiscard]] static std::string get_result_code_description(uint32_t result_code);

private:
    DiameterMessage current_message_;
    bool parse_success_ = false;

    // 内部解析方法
    [[nodiscard]] bool parse_header(const BufferView& buffer, DiameterHeader& header);
    [[nodiscard]] bool parse_avps(const BufferView& buffer, std::vector<DiameterAVP>& avps);
    [[nodiscard]] bool extract_string_avp(const DiameterAVP& avp, std::string& value);
    [[nodiscard]] bool extract_uint32_avp(const DiameterAVP& avp, uint32_t& value);
    [[nodiscard]] bool extract_uint64_avp(const DiameterAVP& avp, uint64_t& value);

    void extract_common_avps(const DiameterMessage& msg);
};

} // namespace protocol_parser::signaling
