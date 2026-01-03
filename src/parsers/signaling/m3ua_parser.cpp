#include "parsers/signaling/m3ua_parser.hpp"
#include <sstream>

namespace protocol_parser::signaling {

std::string M3UAHeader::to_string() const {
    std::ostringstream oss;
    oss << "M3UA Header [Class: " << static_cast<int>(message_class)
        << ", Type: " << static_cast<int>(message_type)
        << ", Length: " << message_length << "]";
    return oss.str();
}

std::string M3UAInfo::get_message_name() const {
    if (static_cast<M3UAMessageClass>(header.message_class) == M3UAMessageClass::ASPStateMaintenanceMessages) {
        switch (static_cast<M3UAMessageType>(header.message_type)) {
            case M3UAMessageType::ASPUP: return "ASP Up";
            case M3UAMessageType::ASPDN: return "ASP Down";
            case M3UAMessageType::ASPAC: return "ASP Active";
            case M3UAMessageType::ASPIA: return "ASP Inactive";
            case M3UAMessageType::BEAT: return "Heartbeat";
            default: return "Unknown ASP";
        }
    }
    return "Unknown";
}

std::string M3UAInfo::to_string() const {
    std::ostringstream oss;
    oss << "M3UA " << get_message_name() << "\n" << header.to_string() << "\n";
    oss << "Parameters: " << parameters.size() << "\n";
    
    if (routing_key.has_value()) {
        oss << "Routing Key: " << routing_key.value() << "\n";
    }
    if (asp_id.has_value()) {
        oss << "ASP ID: " << asp_id.value() << "\n";
    }
    
    return oss.str();
}

const ProtocolInfo& M3UAParser::get_protocol_info() const noexcept {
    static ProtocolInfo info = {"M3UA", 0x305, 8, 16, 2048};
    return info;
}

bool M3UAParser::can_parse(const BufferView& buffer) const noexcept {
    if (buffer.size() < 8) return false;
    // M3UA使用SCTP端口2905
    return buffer[0] == 1;  // Version = 1
}

ParseResult M3UAParser::parse(ParseContext& context) noexcept {
    reset();
    const auto& buffer = context.buffer;

    if (!can_parse(buffer)) {
        return ParseResult::InvalidFormat;
    }

    if (!parse_m3ua_message(buffer, current_info_)) {
        return ParseResult::InvalidFormat;
    }

    context.metadata["m3ua_info"] = current_info_;
    return ParseResult::Success;
}

void M3UAParser::reset() noexcept {
    current_info_ = M3UAInfo{};
    parse_success_ = false;
}

bool M3UAParser::parse_m3ua_message(const BufferView& buffer, M3UAInfo& info) {
    if (!parse_header(buffer, info.header)) {
        return false;
    }

    if (buffer.size() < info.header.message_length) {
        return false;
    }

    BufferView params_buffer = buffer.substr(8, info.header.message_length - 8);
    if (!parse_parameters(params_buffer, info.parameters)) {
        return false;
    }

    // 提取关键字段
    info.parse_timestamp = std::chrono::steady_clock::now();
    info.is_heartbeat = (static_cast<M3UAMessageType>(info.header.message_type) == M3UAMessageType::BEAT);
    info.is_asp_up = (static_cast<M3UAMessageType>(info.header.message_type) == M3UAMessageType::ASPUP);
    info.is_asp_down = (static_cast<M3UAMessageType>(info.header.message_type) == M3UAMessageType::ASPDN);
    info.is_asp_active = (static_cast<M3UAMessageType>(info.header.message_type) == M3UAMessageType::ASPAC);

    return true;
}

bool M3UAParser::parse_header(const BufferView& buffer, M3UAHeader& header) {
    if (buffer.size() < 8) return false;

    header.version = buffer[0];
    header.reserved = buffer[1];
    header.message_class = buffer[2];
    header.message_type = buffer[3];
    header.message_length = (buffer[4] << 24) | (buffer[5] << 16) | 
                           (buffer[6] << 8) | buffer[7];

    if (buffer.size() >= 12) {
        header.correlation_id = (buffer[8] << 24) | (buffer[9] << 16) | 
                               (buffer[10] << 8) | buffer[11];
    }

    return true;
}

bool M3UAParser::parse_parameters(const BufferView& buffer, 
                                 std::vector<std::pair<uint16_t, std::vector<uint8_t>>>& params) {
    size_t offset = 0;
    while (offset + 4 <= buffer.size()) {
        uint16_t tag = (buffer[offset] << 8) | buffer[offset + 1];
        uint16_t length = (buffer[offset + 2] << 8) | buffer[offset + 3];
        offset += 4;

        if (offset + length <= buffer.size()) {
            std::vector<uint8_t> value(buffer.data() + offset, buffer.data() + offset + length);
            params.push_back({tag, value});
            offset += length;

            // 填充到4字节边界
            if (offset % 4 != 0) {
                offset += 4 - (offset % 4);
            }
        } else {
            break;
        }
    }

    return true;
}

} // namespace protocol_parser::signaling
