#include "parsers/signaling/diameter_parser.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace protocol_parser::signaling {

// ========== 辅助函数实现 ==========

uint8_t DiameterAVPFlags::to_uint8() const {
    uint8_t flags = 0;
    if (vendor_specific) flags |= 0x80;
    if (mandatory) flags |= 0x40;
    if (is_private_flag) flags |= 0x20;
    return flags;
}

DiameterAVPFlags DiameterAVPFlags::from_uint8(uint8_t flags) {
    DiameterAVPFlags f;
    f.vendor_specific = (flags & 0x80) != 0;
    f.mandatory = (flags & 0x40) != 0;
    f.is_private_flag = (flags & 0x20) != 0;
    return f;
}

std::string DiameterAVP::to_string() const {
    std::ostringstream oss;
    oss << "AVP [Code: " << code
        << " (" << DiameterParser::get_avp_name(code) << ")"
        << ", Flags: " << (is_mandatory() ? "M" : "")
        << (is_vendor_specific() ? "V" : "")
        << ", Length: " << length << "]";

    if (!data.empty()) {
        oss << " Value: " << get_value_string();
    }

    return oss.str();
}

std::string DiameterAVP::get_value_string() const {
    if (data.empty()) return "<empty>";

    // 尝试解析为字符串
    if (code == static_cast<uint32_t>(DiameterAVPType::SessionId) ||
        code == static_cast<uint32_t>(DiameterAVPType::UserName) ||
        code == static_cast<uint32_t>(DiameterAVPType::OriginHost) ||
        code == static_cast<uint32_t>(DiameterAVPType::OriginRealm)) {
        return std::string(data.begin(), data.end());
    }

    // 尝试解析为整数
    if (data.size() == 4) {
        uint32_t val = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
        return std::to_string(val);
    }

    if (data.size() == 8) {
        uint64_t val = ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) |
                       ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32) |
                       ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16) |
                       ((uint64_t)data[6] << 8) | (uint64_t)data[7];
        return std::to_string(val);
    }

    return "<binary>";
}

std::string DiameterHeader::to_string() const {
    std::ostringstream oss;
    oss << "Diameter Header [Ver: " << static_cast<int>(version)
        << ", Cmd: " << command_code
        << " (" << DiameterParser::get_command_name(command_code) << ")"
        << ", App: " << application_id
        << " (" << DiameterParser::get_application_name(application_id) << ")"
        << ", HbH: 0x" << std::hex << hop_by_hop_id << std::dec
        << ", E2E: 0x" << std::hex << end_to_end_id << std::dec
        << ", Length: " << message_length << "]";
    return oss.str();
}

std::string DiameterMessage::get_command_name() const {
    return DiameterParser::get_command_name(header.command_code);
}

std::string DiameterMessage::get_application_name() const {
    return DiameterParser::get_application_name(header.application_id);
}

std::string DiameterMessage::to_string() const {
    std::ostringstream oss;
    oss << "Diameter " << (header.is_request() ? "Request" : "Answer")
        << " - " << get_command_name() << "\n"
        << header.to_string() << "\n"
        << "AVPs: " << avps.size() << " elements\n";

    if (session_id.has_value()) {
        oss << "Session-ID: " << session_id.value() << "\n";
    }
    if (origin_host.has_value()) {
        oss << "Origin-Host: " << origin_host.value() << "\n";
    }
    if (origin_realm.has_value()) {
        oss << "Origin-Realm: " << origin_realm.value() << "\n";
    }
    if (user_name.has_value()) {
        oss << "User-Name: " << user_name.value() << "\n";
    }
    if (result_code.has_value()) {
        oss << "Result-Code: " << result_code.value()
            << " (" << DiameterParser::get_result_code_description(result_code.value()) << ")\n";
    }

    return oss.str();
}

// ========== DiameterParser 实现 ==========

const ProtocolInfo& DiameterParser::get_protocol_info() const noexcept {
    static ProtocolInfo info = {
        "Diameter",
        0x304,  // Diameter协议类型 (TCP/3868, SCTP)
        20,     // 最小头部大小
        24,     // 最小消息大小
        16777215  // 最大消息大小
    };
    return info;
}

bool DiameterParser::can_parse(const BufferView& buffer) const noexcept {
    if (buffer.size() < 20) return false;

    // 检查Diameter版本 (第1字节)
    if (buffer[0] != 1) return false;

    // 检查消息长度 (第2-4字节)
    uint32_t length = (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
    if (length < 20 || length > 16777215) return false;

    return true;
}

ParseResult DiameterParser::parse(ParseContext& context) noexcept {
    reset();
    const auto& buffer = context.buffer;

    if (!can_parse(buffer)) {
        return ParseResult::InvalidFormat;
    }

    if (!parse_diameter_message(buffer, current_message_)) {
        return ParseResult::InvalidFormat;
    }

    context.metadata["diameter_message"] = current_message_;
    return ParseResult::Success;
}

void DiameterParser::reset() noexcept {
    current_message_ = DiameterMessage{};
    parse_success_ = false;
}

bool DiameterParser::parse_diameter_message(const BufferView& buffer, DiameterMessage& msg) {
    if (buffer.size() < 20) return false;

    // 解析头部
    if (!parse_header(buffer, msg.header)) {
        return false;
    }

    // 检查消息长度
    if (buffer.size() < msg.header.message_length) {
        return false;
    }

    // 解析AVPs
    BufferView avps_buffer = buffer.substr(20, msg.header.message_length - 20);
    if (!parse_avps(avps_buffer, msg.avps)) {
        return false;
    }

    // 提取关键字段
    msg.parse_timestamp = std::chrono::steady_clock::now();
    extract_common_avps(msg);

    return true;
}

DiameterMessage DiameterParser::parse_message(const BufferView& buffer) {
    DiameterMessage msg;
    parse_diameter_message(buffer, msg);
    return msg;
}

bool DiameterParser::parse_header(const BufferView& buffer, DiameterHeader& header) {
    if (buffer.size() < 20) return false;

    // 版本
    header.version = buffer[0];

    // 消息长度 (3字节)
    header.message_length = (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];

    // 标志位
    header.flags = buffer[4];

    // 命令代码 (3字节)
    header.command_code = (buffer[5] << 16) | (buffer[6] << 8) | buffer[7];

    // 应用ID
    header.application_id = (buffer[8] << 24) | (buffer[9] << 16) |
                           (buffer[10] << 8) | buffer[11];

    // Hop-by-Hop ID
    header.hop_by_hop_id = (buffer[12] << 24) | (buffer[13] << 16) |
                           (buffer[14] << 8) | buffer[15];

    // End-to-End ID
    header.end_to_end_id = (buffer[16] << 24) | (buffer[17] << 16) |
                           (buffer[18] << 8) | buffer[19];

    return true;
}

bool DiameterParser::parse_avps(const BufferView& buffer, std::vector<DiameterAVP>& avps) {
    size_t offset = 0;
    while (offset + 8 <= buffer.size()) {
        DiameterAVP avp;

        // AVP代码
        avp.code = (buffer[offset] << 24) | (buffer[offset + 1] << 16) |
                   (buffer[offset + 2] << 8) | buffer[offset + 3];
        offset += 4;

        // AVP标志
        avp.flags = DiameterAVPFlags::from_uint8(buffer[offset]);
        offset += 1;

        // AVP长度 (3字节)
        avp.length = (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
        offset += 3;

        // Vendor-ID (如果存在)
        if (avp.is_vendor_specific() && offset + 4 <= buffer.size()) {
            avp.vendor_id = (buffer[offset] << 24) | (buffer[offset + 1] << 16) |
                            (buffer[offset + 2] << 8) | buffer[offset + 3];
            offset += 4;
        }

        // AVP数据
        size_t data_length = avp.length - 8 - (avp.is_vendor_specific() ? 4 : 0);
        if (offset + data_length <= buffer.size()) {
            avp.data.assign(buffer.data() + offset, buffer.data() + offset + data_length);
            offset += data_length;

            // 填充到4字节边界
            if (offset % 4 != 0) {
                offset += 4 - (offset % 4);
            }

            avps.push_back(avp);
        } else {
            break;
        }
    }

    return true;
}

bool DiameterParser::parse_avp(const BufferView& buffer, DiameterAVP& avp) {
    if (buffer.size() < 8) return false;

    avp.code = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
    avp.flags = DiameterAVPFlags::from_uint8(buffer[4]);
    avp.length = (buffer[5] << 16) | (buffer[6] << 8) | buffer[7];

    if (avp.is_vendor_specific() && buffer.size() >= 12) {
        avp.vendor_id = (buffer[8] << 24) | (buffer[9] << 16) |
                        (buffer[10] << 8) | buffer[11];
    }

    return true;
}

bool DiameterParser::parse_grouped_avp(const BufferView& buffer, std::vector<DiameterAVP>& avps) {
    return parse_avps(buffer, avps);
}

bool DiameterParser::extract_string_avp(const DiameterAVP& avp, std::string& value) {
    if (avp.data.empty()) return false;
    value.assign(avp.data.begin(), avp.data.end());
    return true;
}

bool DiameterParser::extract_uint32_avp(const DiameterAVP& avp, uint32_t& value) {
    if (avp.data.size() < 4) return false;
    value = (avp.data[0] << 24) | (avp.data[1] << 16) |
            (avp.data[2] << 8) | avp.data[3];
    return true;
}

bool DiameterParser::extract_uint64_avp(const DiameterAVP& avp, uint64_t& value) {
    if (avp.data.size() < 8) return false;
    value = ((uint64_t)avp.data[0] << 56) | ((uint64_t)avp.data[1] << 48) |
            ((uint64_t)avp.data[2] << 40) | ((uint64_t)avp.data[3] << 32) |
            ((uint64_t)avp.data[4] << 24) | ((uint64_t)avp.data[5] << 16) |
            ((uint64_t)avp.data[6] << 8) | (uint64_t)avp.data[7];
    return true;
}

void DiameterParser::extract_common_avps(const DiameterMessage& msg) {
    DiameterMessage* mutable_msg = const_cast<DiameterMessage*>(&msg);

    for (const auto& avp : msg.avps) {
        switch (static_cast<DiameterAVPType>(avp.code)) {
            case DiameterAVPType::SessionId: {
                std::string val;
                if (extract_string_avp(avp, val)) {
                    mutable_msg->session_id = val;
                }
                break;
            }
            case DiameterAVPType::OriginHost: {
                std::string val;
                if (extract_string_avp(avp, val)) {
                    mutable_msg->origin_host = val;
                }
                break;
            }
            case DiameterAVPType::OriginRealm: {
                std::string val;
                if (extract_string_avp(avp, val)) {
                    mutable_msg->origin_realm = val;
                }
                break;
            }
            case DiameterAVPType::UserName: {
                std::string val;
                if (extract_string_avp(avp, val)) {
                    mutable_msg->user_name = val;
                }
                break;
            }
            case DiameterAVPType::ResultCode: {
                uint32_t val;
                if (extract_uint32_avp(avp, val)) {
                    mutable_msg->result_code = val;
                }
                break;
            }
            case DiameterAVPType::AuthApplicationId: {
                uint32_t val;
                if (extract_uint32_avp(avp, val)) {
                    mutable_msg->auth_application_id = val;
                }
                break;
            }
            default:
                break;
        }
    }
}

std::string DiameterParser::get_command_name(uint32_t cmd) {
    switch (static_cast<DiameterCommandCode>(cmd)) {
        case DiameterCommandCode::CapabilitiesExchange: return "Capabilities-Exchange";
        case DiameterCommandCode::DeviceWatchdog: return "Device-Watchdog";
        case DiameterCommandCode::DisconnectPeer: return "Disconnect-Peer";
        case DiameterCommandCode::AA: return "AA";
        case DiameterCommandCode::AbortSession: return "Abort-Session";
        case DiameterCommandCode::SessionTermination: return "Session-Termination";
        case DiameterCommandCode::ReAuth: return "Re-Auth";
        case DiameterCommandCode::Accounting: return "Accounting";
        case DiameterCommandCode::EAP: return "EAP";
        default: return "Unknown (" + std::to_string(cmd) + ")";
    }
}

std::string DiameterParser::get_application_name(uint32_t app_id) {
    switch (static_cast<DiameterApplicationId>(app_id)) {
        case DiameterApplicationId::Common: return "Common";
        case DiameterApplicationId::NAS: return "NAS";
        case DiameterApplicationId::MobileIP: return "Mobile-IP";
        case DiameterApplicationId::DiameterBaseAccounting: return "Diameter-Base-Accounting";
        case DiameterApplicationId::CreditControl: return "Credit-Control";
        case DiameterApplicationId::EAP: return "EAP";
        case DiameterApplicationId::SIP: return "SIP";
        case DiameterApplicationId::Gx: return "Gx";
        case DiameterApplicationId::Cx: return "Cx";
        case DiameterApplicationId::Dx: return "Dx";
        case DiameterApplicationId::Sh: return "Sh";
        default: return "Unknown";
    }
}

std::string DiameterParser::get_avp_name(uint32_t avp_code) {
    switch (static_cast<DiameterAVPType>(avp_code)) {
        case DiameterAVPType::UserName: return "User-Name";
        case DiameterAVPType::SessionId: return "Session-Id";
        case DiameterAVPType::OriginHost: return "Origin-Host";
        case DiameterAVPType::OriginRealm: return "Origin-Realm";
        case DiameterAVPType::DestinationHost: return "Destination-Host";
        case DiameterAVPType::DestinationRealm: return "Destination-Realm";
        case DiameterAVPType::ResultCode: return "Result-Code";
        case DiameterAVPType::AuthApplicationId: return "Auth-Application-Id";
        default: return "Unknown";
    }
}

std::string DiameterParser::get_result_code_description(uint32_t result_code) {
    // 高位16位是vendor ID，低位16位是result code
    uint16_t code = result_code & 0xFFFF;

    switch (code) {
        case 2001: return "DIAMETER_SUCCESS";
        case 2002: return "DIAMETER_LIMITED_SUCCESS";
        case 3001: return "DIAMETER_MULTI_ROUND_AUTH";
        case 4001: return "DIAMETER_COMMAND_UNSUPPORTED";
        case 5001: return "DIAMETER_ERROR_USER";
        case 5002: return "DIAMETER_ERROR_REJECTED";
        case 5003: return "DIAMETER_ERROR_NO_RESOURCES";
        default: return "Unknown";
    }
}

} // namespace protocol_parser::signaling
