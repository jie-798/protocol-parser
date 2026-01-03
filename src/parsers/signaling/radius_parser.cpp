#include "parsers/signaling/radius_parser.hpp"
#include <sstream>
#include <iomanip>

namespace protocol_parser::signaling {

std::string RADIUSAttribute::get_type_name() const {
    switch (static_cast<RADIUSAttributeType>(type)) {
        case RADIUSAttributeType::UserName: return "User-Name";
        case RADIUSAttributeType::UserPassword: return "User-Password";
        case RADIUSAttributeType::NASIPAddress: return "NAS-IP-Address";
        case RADIUSAttributeType::NASPort: return "NAS-Port";
        case RADIUSAttributeType::ServiceType: return "Service-Type";
        case RADIUSAttributeType::FramedIPAddress: return "Framed-IP-Address";
        case RADIUSAttributeType::SessionTimeout: return "Session-Timeout";
        case RADIUSAttributeType::CalledStationId: return "Called-Station-Id";
        case RADIUSAttributeType::CallingStationId: return "Calling-Station-Id";
        case RADIUSAttributeType::AcctSessionId: return "Acct-Session-Id";
        default: return "Unknown";
    }
}

std::string RADIUSAttribute::to_string() const {
    std::ostringstream oss;
    oss << "Attribute [Type: " << get_type_name() << " (" << static_cast<int>(type) << ")"
        << ", Length: " << static_cast<int>(length) << "]";
    return oss.str();
}

std::string RADIUSPacket::get_code_name() const {
    switch (static_cast<RADIUSCode>(code)) {
        case RADIUSCode::AccessRequest: return "Access-Request";
        case RADIUSCode::AccessAccept: return "Access-Accept";
        case RADIUSCode::AccessReject: return "Access-Reject";
        case RADIUSCode::AccountingRequest: return "Accounting-Request";
        case RADIUSCode::AccountingResponse: return "Accounting-Response";
        case RADIUSCode::AccessChallenge: return "Access-Challenge";
        default: return "Unknown";
    }
}

std::string RADIUSPacket::to_string() const {
    std::ostringstream oss;
    oss << "RADIUS " << get_code_name() << "\n";
    oss << "Identifier: " << static_cast<int>(identifier) << "\n";
    oss << "Length: " << length << "\n";
    oss << "Attributes: " << attributes.size() << "\n";

    if (user_name.has_value()) {
        oss << "User-Name: " << user_name.value() << "\n";
    }
    if (framed_ip_address.has_value()) {
        uint32_t ip = framed_ip_address.value();
        oss << "Framed-IP-Address: " << ((ip >> 24) & 0xFF) << "."
            << ((ip >> 16) & 0xFF) << "." << ((ip >> 8) & 0xFF) << "." << (ip & 0xFF) << "\n";
    }

    return oss.str();
}

const ProtocolInfo& RADIUSParser::get_protocol_info() const noexcept {
    static ProtocolInfo info = {"RADIUS", 0x306, 4, 20, 4096};
    return info;
}

bool RADIUSParser::can_parse(const BufferView& buffer) const noexcept {
    if (buffer.size() < 20) return false;
    // RADIUS使用UDP端口1812/1813
    return buffer.size() >= 20;
}

ParseResult RADIUSParser::parse(ParseContext& context) noexcept {
    reset();
    const auto& buffer = context.buffer;

    if (!can_parse(buffer)) {
        return ParseResult::InvalidFormat;
    }

    if (!parse_radius_packet(buffer, current_packet_)) {
        return ParseResult::InvalidFormat;
    }

    context.metadata["radius_packet"] = current_packet_;
    return ParseResult::Success;
}

void RADIUSParser::reset() noexcept {
    current_packet_ = RADIUSPacket{};
    parse_success_ = false;
}

bool RADIUSParser::parse_radius_packet(const BufferView& buffer, RADIUSPacket& packet) {
    if (buffer.size() < 20) return false;

    packet.code = buffer[0];
    packet.identifier = buffer[1];
    packet.length = (buffer[2] << 8) | buffer[3];

    // 复制认证符
    std::copy(buffer.data() + 4, buffer.data() + 20, packet.authenticator);

    // 解析属性
    BufferView attrs_buffer = buffer.substr(20, packet.length - 20);
    if (!parse_attributes(attrs_buffer, packet.attributes)) {
        return false;
    }

    // 提取关键字段
    packet.parse_timestamp = std::chrono::steady_clock::now();
    packet.is_request = (packet.code == static_cast<uint8_t>(RADIUSCode::AccessRequest) ||
                         packet.code == static_cast<uint8_t>(RADIUSCode::AccountingRequest));
    packet.is_response = !packet.is_request;
    packet.is_accounting = (packet.code == static_cast<uint8_t>(RADIUSCode::AccountingRequest) ||
                            packet.code == static_cast<uint8_t>(RADIUSCode::AccountingResponse));

    return true;
}

bool RADIUSParser::parse_attributes(const BufferView& buffer, std::vector<RADIUSAttribute>& attrs) {
    size_t offset = 0;
    while (offset + 2 <= buffer.size()) {
        RADIUSAttribute attr;
        attr.type = buffer[offset];
        attr.length = buffer[offset + 1];
        offset += 2;

        if (attr.length < 2 || offset + attr.length - 2 > buffer.size()) {
            break;
        }

        if (attr.length > 2) {
            attr.value.assign(buffer.data() + offset, buffer.data() + offset + attr.length - 2);
        }

        attrs.push_back(attr);
        offset += attr.length - 2;
    }

    return true;
}

bool RADIUSParser::extract_string_attr(const RADIUSAttribute& attr, std::string& value) {
    if (attr.value.empty()) return false;
    value.assign(attr.value.begin(), attr.value.end());
    return true;
}

bool RADIUSParser::extract_uint32_attr(const RADIUSAttribute& attr, uint32_t& value) {
    if (attr.value.size() != 4) return false;
    value = (attr.value[0] << 24) | (attr.value[1] << 16) | 
            (attr.value[2] << 8) | attr.value[3];
    return true;
}

} // namespace protocol_parser::signaling
