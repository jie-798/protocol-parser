#pragma once

#include "../../parsers/base_parser.hpp"
#include "../../core/buffer_view.hpp"
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace protocol_parser::signaling {

// 使用父命名空间的类型
using protocol_parser::parsers::ProtocolInfo;
using protocol_parser::parsers::ParseResult;
using protocol_parser::parsers::ParseContext;
using protocol_parser::core::BufferView;

// S1AP协议类型 (3GPP TS 36.413)
enum class S1APProcedureCode : uint8_t {
    InitialUEMessage = 11,
    UplinkNASTransport = 12,
    DownlinkNASTransport = 13,
    InitialContextSetup = 9,
    UEContextRelease = 14,
    PathSwitchRequest = 23,
    HandoverPreparation = 16,
    HandoverResourceAllocation = 17,
    E_RABSetup = 21,
    E_RABModify = 22,
    E_RABRelease = 23,
    Paging = 24
};

// S1AP消息类型
enum class S1APMessageType : uint8_t {
    InitiatingMessage = 1,
    SuccessfulOutcome = 2,
    UnsuccessfulOutcome = 3
};

// S1AP PDU结构
struct S1APPDU {
    S1APMessageType message_type;
    uint8_t procedure_code;
    std::vector<uint8_t> criticality;
    std::vector<uint8_t> message_structure;

    [[nodiscard]] std::string get_procedure_name() const;
    [[nodiscard]] std::string to_string() const;
};

// S1AP信息
struct S1APInfo {
    S1APPDU pdu;

    // 解析后的关键字段
    std::optional<std::string> mme_ue_s1ap_id;
    std::optional<std::string> enb_ue_s1ap_id;
    std::optional<std::string> nas_pdu;
    std::optional<uint16_t> tai_mcc;
    std::optional<uint16_t> tai_mnc;
    std::optional<uint32_t> ecgi;

    // 元数据
    bool is_request = false;
    bool is_response = false;
    bool is_error = false;
    std::chrono::steady_clock::time_point parse_timestamp;

    [[nodiscard]] std::string to_string() const;
};

// S1AP解析器 (简化版，完整需要ASN.1编译器)
class S1APParser : public protocol_parser::parsers::BaseParser {
public:
    S1APParser() = default;
    ~S1APParser() override = default;

    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    [[nodiscard]] bool parse_s1ap_pdu(const BufferView& buffer, S1APPDU& pdu);

private:
    S1APInfo current_info_;
};
} // namespace protocol_parser::signaling
