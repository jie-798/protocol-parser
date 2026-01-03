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

// X2AP/XnAP过程代码 (3GPP TS 36.423 / 38.423)
enum class X2APProcedureCode : uint8_t {
    // 切换相关
    HandoverRequest = 1,
    HandoverRequestAcknowledge = 2,
    HandoverFailure = 3,
    HandoverCancel = 4,
    
    // 切换准备
    HandoverPreparation = 10,
    HandoverResourceAllocation = 11,
    
    // SN状态转移
    SNStatusTransfer = 12,
    
    // UE上下文释放
    UEContextRelease = 15,
    
    // 错误指示
    ErrorIndication = 16,
    
    // X2/Xn接口建立
    X2Setup = 18,
    XnSetup = 18
};

// X2AP/XnAP消息类型
enum class X2APMessageType : uint8_t {
    InitiatingMessage = 1,
    SuccessfulOutcome = 2,
    UnsuccessfulOutcome = 3
};

// X2AP/XnAP关键信息
struct X2APInfo {
    X2APMessageType message_type;
    uint8_t procedure_code;
    std::string enb1_id;
    std::string enb2_id;
    std::vector<uint8_t> payload;
    
    [[nodiscard]] std::string get_procedure_name() const;
    [[nodiscard]] std::string to_string() const;
};

// X2AP/XnAP解析器（LTE/5G基站间接口）
class X2APParser : public protocol_parser::parsers::BaseParser {
public:
    X2APParser() = default;
    ~X2APParser() override = default;

    [[nodiscard]] const ProtocolInfo& get_protocol_info() const noexcept override;
    [[nodiscard]] bool can_parse(const BufferView& buffer) const noexcept override;
    [[nodiscard]] ParseResult parse(ParseContext& context) noexcept override;
    void reset() noexcept override;

private:
    X2APInfo current_info_;
};

} // namespace protocol_parser::signaling
