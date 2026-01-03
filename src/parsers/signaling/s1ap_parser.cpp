#include "parsers/signaling/s1ap_parser.hpp"
#include <sstream>

namespace protocol_parser::signaling {

std::string S1APPDU::get_procedure_name() const {
    switch (static_cast<S1APProcedureCode>(procedure_code)) {
        case S1APProcedureCode::InitialUEMessage: return "Initial UE Message";
        case S1APProcedureCode::UplinkNASTransport: return "Uplink NAS Transport";
        case S1APProcedureCode::DownlinkNASTransport: return "Downlink NAS Transport";
        default: return "Unknown";
    }
}

std::string S1APPDU::to_string() const {
    std::ostringstream oss;
    oss << "S1AP PDU [Type: " << static_cast<int>(message_type)
        << ", Procedure: " << get_procedure_name() << "]";
    return oss.str();
}

std::string S1APInfo::to_string() const {
    std::ostringstream oss;
    oss << pdu.to_string();
    return oss.str();
}

const ProtocolInfo& S1APParser::get_protocol_info() const noexcept {
    static ProtocolInfo info = {"S1AP", 0x301, 4, 8, 4096};
    return info;
}

bool S1APParser::can_parse(const BufferView& buffer) const noexcept {
    return buffer.size() >= 4 && buffer[0] == 0x00;
}

ParseResult S1APParser::parse(ParseContext& context) noexcept {
    return ParseResult::Success;
}

void S1APParser::reset() noexcept {}

bool S1APParser::parse_s1ap_pdu(const BufferView& buffer, S1APPDU& pdu) {
    if (buffer.size() < 4) return false;
    pdu.message_type = static_cast<S1APMessageType>(buffer[0]);
    pdu.procedure_code = buffer[1];
    return true;
}

} // namespace protocol_parser::signaling
