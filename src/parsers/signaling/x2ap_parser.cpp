#include "parsers/signaling/x2ap_parser.hpp"
#include <sstream>

namespace protocol_parser::signaling {

std::string X2APInfo::get_procedure_name() const {
    switch (static_cast<X2APProcedureCode>(procedure_code)) {
        case X2APProcedureCode::HandoverRequest: return "Handover Request";
        case X2APProcedureCode::HandoverRequestAcknowledge: return "Handover Request Ack";
        case X2APProcedureCode::HandoverFailure: return "Handover Failure";
        case X2APProcedureCode::HandoverCancel: return "Handover Cancel";
        case X2APProcedureCode::SNStatusTransfer: return "SN Status Transfer";
        case X2APProcedureCode::UEContextRelease: return "UE Context Release";
        case X2APProcedureCode::X2Setup: return "X2/Xn Setup";
        default: return "Unknown";
    }
}

std::string X2APInfo::to_string() const {
    std::ostringstream oss;
    oss << "X2AP/XnAP [Type: " << static_cast<int>(message_type)
        << ", Procedure: " << get_procedure_name() << "]";
    return oss.str();
}

const ProtocolInfo& X2APParser::get_protocol_info() const noexcept {
    static ProtocolInfo info = {"X2AP/XnAP", 0x303, 4, 8, 4096};
    return info;
}

bool X2APParser::can_parse(const BufferView& buffer) const noexcept {
    return buffer.size() >= 4;
}

ParseResult X2APParser::parse(ParseContext& context) noexcept {
    return ParseResult::Success;
}

void X2APParser::reset() noexcept {}

} // namespace protocol_parser::signaling
