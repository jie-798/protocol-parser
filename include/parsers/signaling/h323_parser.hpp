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

// H.323消息类型 (ITU-T H.323)
enum class H323MessageType : uint8_t {
    Setup = 0x05,
    CallProceeding = 0x02,
    Alerting = 0x01,
    Connect = 0x07,
    ReleaseComplete = 0x5A,
    Facility = 0x62,
    Progress = 0x03,
    UserInformation = 0x20,
    Notify = 0x6E
};

// H.323协议元素
enum class H323ProtocolType : uint8_t {
    Q931 = 0x08,
    H245 = 0x0A,
    RTP = 0x0C,
    RTCP = 0x0D,
    H225 = 0x0E,
    T120 = 0x0F
};

// Q.931消息原因值
enum class Q931Cause : uint8_t {
    NormalCallClearing = 16,
    UserBusy = 17,
    NoUserResponding = 18,
    UserAlertingNoAnswer = 19,
    CallRejected = 21,
    NumberChanged = 22,
    DestinationOutOfOrder = 27,
    NoCircuitChannelAvailable = 34,
    NetworkOutOfOrder = 38,
    TemporaryFailure = 41,
    SwitchingEquipmentCongestion = 42,
    AccessInformationDiscarded = 43,
    RequestedCircuitNotAvailable = 44,
    PrecedenceCallBlocked = 49,
    NormalUnspecified = 31
};

// H.323呼叫信息
struct H323CallInfo {
    H323MessageType message_type;
    uint8_t protocol_discriminator;
    uint8_t call_reference_length;
    std::vector<uint8_t> call_reference;
    uint8_t message_type_q931;

    // 解析后的关键字段
    std::optional<std::string> calling_number;
    std::optional<std::string> called_number;
    std::optional<Q931Cause> cause;
    std::optional<std::string> display;

    // H.245信息
    std::optional<std::string> h245_address;
    std::optional<uint16_t> h245_port;

    // 元数据
    bool is_setup = false;
    bool is_connect = false;
    bool is_release = false;
    std::string error_message;
    std::chrono::steady_clock::time_point parse_timestamp;

    [[nodiscard]] std::string get_message_name() const;
    [[nodiscard]] std::string to_string() const;
};

// H.323解析器框架（包含Q.931, H.245, H.225, RAS）
class H323Parser : public protocol_parser::parsers::BaseParser {
public:
    H323Parser() = default;
    ~H323Parser() override = default;

    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    [[nodiscard]] bool parse_h323_message(const BufferView& buffer, H323CallInfo& info);
    [[nodiscard]] bool parse_q931_message(const BufferView& buffer, H323CallInfo& info);
    [[nodiscard]] bool parse_h245_message(const BufferView& buffer, H323CallInfo& info);

private:
    H323CallInfo current_info_;
    bool parse_success_ = false;
};

} // namespace protocol_parser::signaling
