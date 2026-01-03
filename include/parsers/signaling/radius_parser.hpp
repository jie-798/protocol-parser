#pragma once

#include "../../parsers/base_parser.hpp"
#include "../../core/buffer_view.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace protocol_parser::signaling {

using protocol_parser::parsers::ProtocolInfo;
using protocol_parser::parsers::ParseResult;
using protocol_parser::parsers::ParseContext;
using protocol_parser::core::BufferView;

// RADIUS消息类型 (RFC 2865)
enum class RADIUSCode : uint8_t {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccountingRequest = 4,
    AccountingResponse = 5,
    AccessChallenge = 11,
    StatusServer = 12,
    StatusClient = 13
};

// RADIUS属性类型
enum class RADIUSAttributeType : uint8_t {
    UserName = 1,
    UserPassword = 2,
    NASIPAddress = 4,
    NASPort = 5,
    ServiceType = 6,
    FramedProtocol = 7,
    FramedIPAddress = 8,
    FramedIPNetmask = 9,
    FramedRouting = 10,
    FilterId = 11,
    FramedMTU = 12,
    FramedCompression = 13,
    LoginIPHost = 14,
    LoginService = 15,
    ReplyMessage = 18,
    CallbackNumber = 19,
    CallbackId = 20,
    FramedRoute = 22,
    FramedIPXNetwork = 23,
    State = 24,
    Class = 25,
    VendorSpecific = 26,
    SessionTimeout = 27,
    IdleTimeout = 28,
    TerminationAction = 29,
    CalledStationId = 30,
    CallingStationId = 31,
    NASIdentifier = 32,
    ProxyState = 33,
    LoginLATService = 34,
    LoginLATNode = 35,
    LoginLATGroup = 36,
    FramedAppleTalkLink = 37,
    FramedAppleTalkNetwork = 38,
    AcctDelayTime = 41,
    AcctInputOctets = 42,
    AcctOutputOctets = 43,
    AcctSessionId = 44,
    AcctAuthentic = 45,
    AcctSessionTime = 46,
    AcctInputPackets = 47,
    AcctOutputPackets = 48,
    AcctTerminateCause = 49,
    AcctMultiSessionId = 50,
    AcctLinkCount = 51,
    AcctInputGigawords = 52,
    AcctOutputGigawords = 53,
    EventTimestamp = 55,
    EgressVLANID = 56,
    IngressFilters = 57,
    EgressVLANName = 58,
    UserPriorityTable = 59,
    CHAPPassword = 60,
    NASPortType = 61,
    PortLimit = 62,
    LoginLATPort = 63,
    TunnelType = 64,
    TunnelMediumType = 65,
    TunnelClientEndpoint = 66,
    TunnelServerEndpoint = 67,
    TunnelPassword = 69,
    ARAPPassword = 70,
    ARAPFeatures = 71,
    ARAPZoneAccess = 72,
    ARAPSecurity = 73,
    ARAPSecurityData = 74,
    PasswordRetry = 75,
    Prompt = 76,
    ConnectInfo = 77,
    ConfigurationToken = 78,
    EAPMessage = 79,
    MessageAuthenticator = 80,
    TunnelPrivateGroupID = 81,
    TunnelAssignmentID = 82,
    TunnelPreference = 83
};

// RADIUS属性
struct RADIUSAttribute {
    uint8_t type;
    uint8_t length;
    std::vector<uint8_t> value;

    [[nodiscard]] std::string get_type_name() const;
    [[nodiscard]] std::string to_string() const;
};

// RADIUS数据包
struct RADIUSPacket {
    uint8_t code;
    uint8_t identifier;
    uint16_t length;
    uint8_t authenticator[16];
    std::vector<RADIUSAttribute> attributes;

    // 解析后的关键字段
    std::optional<std::string> user_name;
    std::optional<std::string> user_password;
    std::optional<uint32_t> nas_ip_address;
    std::optional<uint32_t> framed_ip_address;
    std::optional<uint32_t> acct_session_id;
    std::optional<std::string> session_id;
    std::optional<uint16_t> nas_port;
    std::optional<std::string> called_station_id;
    std::optional<std::string> calling_station_id;

    // 元数据
    bool is_request = false;
    bool is_response = false;
    bool is_accounting = false;
    std::string error_message;
    std::chrono::steady_clock::time_point parse_timestamp;

    [[nodiscard]] std::string get_code_name() const;
    [[nodiscard]] std::string to_string() const;
};

// RADIUS解析器
class RADIUSParser : public protocol_parser::parsers::BaseParser {
public:
    RADIUSParser() = default;
    ~RADIUSParser() override = default;

    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    [[nodiscard]] bool parse_radius_packet(const BufferView& buffer, RADIUSPacket& packet);

private:
    RADIUSPacket current_packet_;
    bool parse_success_ = false;

    [[nodiscard]] bool parse_attributes(const BufferView& buffer, std::vector<RADIUSAttribute>& attrs);
    [[nodiscard]] bool extract_string_attr(const RADIUSAttribute& attr, std::string& value);
    [[nodiscard]] bool extract_uint32_attr(const RADIUSAttribute& attr, uint32_t& value);
};

} // namespace protocol_parser::signaling
