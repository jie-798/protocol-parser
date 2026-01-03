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

// M3UA消息类别 (RFC 4666)
enum class M3UAMessageClass : uint8_t {
    ManagementMessages = 0,
    TransferMessages = 1,
    SS7SignalingNetworkManagementMessages = 2,
    ASPStateMaintenanceMessages = 3,
    ASPTrafficMaintenanceMessages = 4,
    RoutingKeyManagementMessages = 5
};

// M3UA消息类型
enum class M3UAMessageType : uint8_t {
    // ASP状态维护
    ASPUP = 3,       // ASP Up
    ASPDN = 4,       // ASP Down
    ASPAC = 5,       // ASP Active
    ASPIA = 6,       // ASP Inactive
    BEAT = 2,        // Heartbeat
    
    // 管理消息
    NTFY = 1,        // Notification
    ERROR = 0        // Error Message
};

// M3UA参数标签
enum class M3UAParamTag : uint16_t {
    NetworkAppearance = 0x0200,
    RoutingKey = 0x0006,
    CorrelationId = 0x0007,
    DiagnosticInformation = 0x0008,
    HeartbeatData = 0x0009,
    TrafficModeType = 0x000b,
    ErrorCode = 0x000c,
    Status = 0x000d,
    ASPIdentifier = 0x0011,
    AffectedPointCode = 0x0012,
    CongestionIndications = 0x0014
};

// M3UA消息头
struct M3UAHeader {
    uint8_t version = 1;
    uint8_t reserved = 0;
    uint8_t message_class;
    uint8_t message_type;
    uint32_t message_length;
    uint32_t correlation_id;

    [[nodiscard]] std::string to_string() const;
};

// M3UA消息信息
struct M3UAInfo {
    M3UAHeader header;
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> parameters;

    // 解析后的关键字段
    std::optional<uint32_t> routing_key;
    std::optional<uint32_t> network_appearance;
    std::optional<uint16_t> asp_id;
    std::optional<uint8_t> traffic_mode;
    std::optional<uint16_t> error_code;
    std::optional<uint8_t> status;

    // 元数据
    bool is_asp_up = false;
    bool is_asp_down = false;
    bool is_asp_active = false;
    bool is_heartbeat = false;
    std::chrono::steady_clock::time_point parse_timestamp;

    [[nodiscard]] std::string get_message_name() const;
    [[nodiscard]] std::string to_string() const;
};

// M3UA解析器 (SIGTRAN MTP3用户适配)
class M3UAParser : public protocol_parser::parsers::BaseParser {
public:
    M3UAParser() = default;
    ~M3UAParser() override = default;

    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    [[nodiscard]] bool parse_m3ua_message(const BufferView& buffer, M3UAInfo& info);

private:
    M3UAInfo current_info_;
    bool parse_success_ = false;

    [[nodiscard]] bool parse_header(const BufferView& buffer, M3UAHeader& header);
    [[nodiscard]] bool parse_parameters(const BufferView& buffer, 
                                       std::vector<std::pair<uint16_t, std::vector<uint8_t>>>& params);
};

} // namespace protocol_parser::signaling
