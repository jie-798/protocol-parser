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

// GTPv2-C 消息类型 (3GPP TS 29.274)
enum class GTPv2MessageType : uint8_t {
    // Echo相关
    EchoRequest = 1,
    EchoResponse = 2,

    // 会话管理消息
    CreateSessionRequest = 32,
    CreateSessionResponse = 33,
    ModifyBearerRequest = 34,
    ModifyBearerResponse = 35,
    DeleteSessionRequest = 36,
    DeleteSessionResponse = 37,

    // 承载管理
    CreateBearerRequest = 86,
    CreateBearerResponse = 87,
    UpdateBearerRequest = 88,
    UpdateBearerResponse = 89,
    DeleteBearerRequest = 90,
    DeleteBearerResponse = 91,

    // UE相关
    DownlinkDataNotification = 130,
    DownlinkDataNotificationAck = 131,

    // 错误指示
    ErrorIndication = 26
};

// GTPv2 信息元素 (IE) 类型
enum class GTPv2IEType : uint16_t {
    IMSI = 1,
    Cause = 2,
    Recovery = 3,
    APN = 71,
    AMBR = 72,
    EBI = 73,
    IPv4 = 74,
    IPv6 = 75,
    MEI = 76,
    MSISDN = 77,
    Indication = 78,
    PDNType = 79,
    PAA = 80,
    BearerQoS = 81,
    FlowQoS = 82,
    RATType = 83,
    ServingNetwork = 84,
    BearerContext = 87,
    ChargingID = 94,
    PDNConnection = 109,
    UETimeZone = 114,
    UserLocationInformation = 115,
    FTEID = 127,
    UCI = 134
};

// 原因值 (Cause)
enum class GTPv2Cause : uint8_t {
    // 成功原因
    RequestAccepted = 16,
    RequestAcceptedPartial = 17,
    NewPDNTypeDueToSingleAddressBearing = 18,

    // 错误原因
    LocalDetached = 19,
    CompleteDetached = 20,
    RATChangedFrom3GPPToNon3GPP = 21,
    PreferredPDNConnectionsNotSupported = 22,
    PDNTypeNotAllowedOnlyIPv4 = 23,
    PDNTypeNotAllowedOnlyIPv6 = 24,
    PDNTypeNotAllowedIPv4v6 = 25,
    OnlyIPv4Allowed = 26,
    OnlyIPv6Allowed = 27,
    OnlyIPv4v6Allowed = 28,
    PDNTypeIPv4Allowed = 29,
    PDNTypeIPv6Allowed = 30,
    PDNTypeIPv4v6Allowed = 31,
    ResourcesUnavailable = 32,
    MaxNumberOfPDNReached = 33,
    UnknownAPN = 34,
    InvalidPeer = 35,
    APNAccessDenied = 36,
    APNCongestion = 37,
    NoMemoryAvailable = 38,
    RetryUponUserInitiatedDetach = 39,
    InvalidMandatoryInformation = 40,
    MissingOrUnknownAPN = 41,
    ContextNotFound = 42,
    InvalidMessageFormat = 44,
    VersionNotSupported = 45,
    InvalidLength = 46
};

// F-TEID (Fully Qualified TEID) 结构
struct GTFTEID {
    bool ipv4_present = false;
    bool ipv6_present = false;
    uint8_t interface_type = 0;
    uint32_t teid = 0;
    uint32_t ipv4_address = 0;
    uint8_t ipv6_address[16] = {0};

    [[nodiscard]] std::string to_string() const;
};

// EPS Bearer QoS
struct EPSBearerQoS {
    uint8_t qci = 0;                  // QoS Class Identifier
    uint64_t mbr_dl = 0;              // Maximum Bit Rate Downlink (bps)
    uint64_t mbr_ul = 0;              // Maximum Bit Rate Uplink
    uint64_t gbr_dl = 0;              // Guaranteed Bit Rate Downlink
    uint64_t gbr_ul = 0;              // Guaranteed Bit Rate Uplink

    [[nodiscard]] std::string to_string() const;
};

// Bearer Context
struct BearerContext {
    uint8_t ebi = 0;                  // EPS Bearer ID
    GTFTEID s1_u_enodeb_fteid;        // eNodeB侧F-TEID
    GTFTEID s1_u_sgw_fteid;           // SGW侧F-TEID
    EPSBearerQoS qos;
    uint8_t tft_operation = 0;        // Traffic Flow Template

    [[nodiscard]] std::string to_string() const;
};

// GTPv2 消息头
struct GTPv2Header {
    uint8_t version = 2;              // GTP版本 (2)
    bool piggybacking = false;        // 是否有piggybacking
    bool teid_present = false;        // TEID是否存在
    uint8_t message_type = 0;         // 消息类型
    uint32_t teid = 0;                // Tunnel Endpoint Identifier
    uint16_t sequence_number = 0;     // 序列号
    uint8_t spare = 0;                // 备用位
    uint16_t message_length = 0;      // 消息长度（不包括头）

    [[nodiscard]] std::string to_string() const;
};

// GTPv2 IE (Information Element)
struct GTPv2IE {
    uint16_t type = 0;
    uint16_t length = 0;
    uint8_t instance = 0;
    std::vector<uint8_t> value;

    [[nodiscard]] std::string to_string() const;
};

// GTPv2 解析结果
struct GTPv2Info {
    GTPv2Header header;
    std::vector<GTPv2IE> ies;

    // 解析后的关键字段
    std::optional<std::vector<uint8_t>> imsi;
    std::optional<GTPv2Cause> cause;
    std::optional<std::string> apn;
    std::optional<GTFTEID> sender_fteid;
    std::optional<GTFTEID> receiver_fteid;
    std::vector<BearerContext> bearer_contexts;
    std::optional<uint32_t> charging_id;
    std::optional<uint32_t> mme_s11_sgw_s12_fteid;
    std::optional<uint8_t> pdn_type;

    // 元数据
    bool is_request = false;
    bool is_response = false;
    bool is_error = false;
    std::string error_message;
    std::chrono::steady_clock::time_point parse_timestamp;

    [[nodiscard]] std::string get_message_name() const;
    [[nodiscard]] std::string to_string() const;
};

// GTPv2-C 解析器
class GTPv2Parser : public protocol_parser::parsers::BaseParser {
public:
    GTPv2Parser() = default;
    ~GTPv2Parser() override = default;

    // BaseParser接口实现
    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    // GTPv2特定接口
    [[nodiscard]] bool parse_gtpv2_message(const BufferView& buffer, GTPv2Info& info);
    [[nodiscard]] GTPv2Info parse_gtpv2_header(const BufferView& buffer);

    // IE解析接口
    [[nodiscard]] bool parse_ie(const BufferView& buffer, GTPv2IE& ie);
    [[nodiscard]] bool parse_fteid(const BufferView& buffer, GTFTEID& fteid);
    [[nodiscard]] bool parse_bearer_qos(const BufferView& buffer, EPSBearerQoS& qos);
    [[nodiscard]] bool parse_bearer_context(const BufferView& buffer, BearerContext& ctx);

    // 工具方法
    [[nodiscard]] static std::string get_message_type_name(uint8_t type);
    [[nodiscard]] static std::string get_cause_name(GTPv2Cause cause);
    [[nodiscard]] static std::string get_ie_type_name(uint16_t ie_type);

private:
    GTPv2Info current_info_;
    bool parse_success_ = false;

    // 内部解析方法
    [[nodiscard]] bool parse_header(const BufferView& buffer, GTPv2Header& header);
    [[nodiscard]] bool parse_ies(const BufferView& buffer, std::vector<GTPv2IE>& ies);
    [[nodiscard]] bool extract_imsi(const GTPv2IE& ie, std::vector<uint8_t>& imsi);
    [[nodiscard]] bool extract_cause(const GTPv2IE& ie, GTPv2Cause& cause);
    [[nodiscard]] bool extract_apn(const GTPv2IE& ie, std::string& apn);
    [[nodiscard]] bool extract_fteid(const GTPv2IE& ie, GTFTEID& fteid);
    [[nodiscard]] bool extract_charging_id(const GTPv2IE& ie, uint32_t& charging_id);

    [[nodiscard]] bool is_request_message(uint8_t type) const;
    [[nodiscard]] bool is_response_message(uint8_t type) const;
    [[nodiscard]] bool is_error_indication(uint8_t type) const;
};

} // namespace protocol_parser::signaling
