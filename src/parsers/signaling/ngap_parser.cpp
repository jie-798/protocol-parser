#include "parsers/signaling/ngap_parser.hpp"
#include <sstream>

namespace protocol_parser::signaling {

std::string NGAPPDU::get_procedure_name() const {
    switch (static_cast<NGAPProcedureCode>(procedure_code)) {
        case NGAPProcedureCode::InitialUEMessage: return "Initial UE Message";
        case NGAPProcedureCode::UplinkNASTransport: return "Uplink NAS Transport";
        case NGAPProcedureCode::DownlinkNASTransport: return "Downlink NAS Transport";
        case NGAPProcedureCode::InitialContextSetup: return "Initial Context Setup";
        case NGAPProcedureCode::UEContextRelease: return "UE Context Release";
        case NGAPProcedureCode::HandoverPreparation: return "Handover Preparation";
        case NGAPProcedureCode::HandoverResourceAllocation: return "Handover Resource Allocation";
        case NGAPProcedureCode::PDUSessionResourceSetup: return "PDU Session Resource Setup";
        case NGAPProcedureCode::Paging: return "Paging";
        default: return "Unknown";
    }
}

std::string NGAPPDU::to_string() const {
    std::ostringstream oss;
    oss << "NGAP PDU [Type: " << static_cast<int>(message_type)
        << ", Procedure: " << get_procedure_name() << "]";
    return oss.str();
}

std::string NGAPInfo::to_string() const {
    std::ostringstream oss;
    oss << pdu.to_string();
    return oss.str();
}

const ProtocolInfo& NGAPParser::get_protocol_info() const noexcept {
    static ProtocolInfo info = {"NGAP", 0x302, 4, 8, 4096};
    return info;
}

bool NGAPParser::can_parse(const BufferView& buffer) const noexcept {
    return buffer.size() >= 4 && buffer[0] == 0x00;
}

ParseResult NGAPParser::parse(ParseContext& context) noexcept {
    return ParseResult::Success;
}

void NGAPParser::reset() noexcept {}

bool NGAPParser::parse_ngap_pdu(const BufferView& buffer, NGAPPDU& pdu) {
    if (buffer.size() < 4) return false;
    pdu.message_type = static_cast<NGAPMessageType>(buffer[0]);
    pdu.procedure_code = buffer[1];
    return true;
}

} // namespace protocol_parser::signaling
