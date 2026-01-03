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

// NGAP协议类型 (3GPP TS 38.413)
enum class NGAPProcedureCode : uint8_t {
    // 初始相关
    InitialUEMessage = 19,
    UplinkNASTransport = 20,
    DownlinkNASTransport = 21,
    
    // UE上下文管理
    InitialContextSetup = 22,
    UEContextRelease = 23,
    UEContextModification = 24,
    
    // 切换相关
    HandoverPreparation = 33,
    HandoverResourceAllocation = 34,
    HandoverNotification = 35,
    HandoverCancel = 36,
    
    // PDU会话
    PDUSessionResourceSetup = 27,
    PDUSessionResourceModify = 28,
    PDUSessionResourceRelease = 29,
    
    // 寻呼
    Paging = 32,
    
    // 错误指示
    ErrorIndication = 30
};

// NGAP消息类型
enum class NGAPMessageType : uint8_t {
    InitiatingMessage = 1,
    SuccessfulOutcome = 2,
    UnsuccessfulOutcome = 3
};

// NGAP关键IE类型
enum class NGAPCriticality : uint8_t {
    Reject = 0,
    Ignore = 1,
    Notify = 2
};

// NGAP IE标识
enum class NGAP_IE : uint16_t {
    AMF_UE_NGAP_ID = 1,
    RAN_UE_NGAP_ID = 2,
    NAS_PDU = 4,
    UE_AMBR = 447,
    PDUSessionResourceSetupList = 65,
    PDUSessionResourceReleaseList = 66,
    PDUSessionResourceToReleaseList = 67,
    PDUSessionType = 274,
    QoSFlowSetupRequestList = 329,
    QoSFlowModifyList = 330,
    SecurityContext = 115,
    GUAMI = 115,
    UserLocationInformation = 137,
    RAT_FrequencyPriorityInformation = 156,
    PDU_session_ResourceSetupRequest = 202,
    PDU_session_ResourceSetupList = 203,
    PDU_session_ResourceReleaseCommand = 204,
    PDU_session_ResourceReleaseList = 205
};

// NGAP PDU结构
struct NGAPPDU {
    NGAPMessageType message_type;
    uint8_t procedure_code;
    NGAPCriticality criticality;
    std::vector<uint8_t> procedure_criticality;
    std::vector<uint8_t> message_structure;

    [[nodiscard]] std::string get_procedure_name() const;
    [[nodiscard]] std::string to_string() const;
};

// NGAP信息
struct NGAPInfo {
    NGAPPDU pdu;

    // 解析后的关键字段
    std::optional<std::string> amf_ue_ngap_id;
    std::optional<std::string> ran_ue_ngap_id;
    std::optional<std::vector<uint8_t>> nas_pdu;
    std::optional<uint32_t> pdu_session_id;
    std::optional<std::string> tai;
    std::optional<std::string> nr_cgi;

    // 元数据
    bool is_request = false;
    bool is_response = false;
    bool is_error = false;
    std::string error_message;
    std::chrono::steady_clock::time_point parse_timestamp;

    [[nodiscard]] std::string to_string() const;
};

// NGAP解析器
class NGAPParser : public protocol_parser::parsers::BaseParser {
public:
    NGAPParser() = default;
    ~NGAPParser() override = default;

    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

    [[nodiscard]] bool parse_ngap_pdu(const BufferView& buffer, NGAPPDU& pdu);

private:
    NGAPInfo current_info_;
    bool parse_success_ = false;
};

} // namespace protocol_parser::signaling
