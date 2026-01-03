#include "parsers/signaling/gtppv2_parser.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace protocol_parser::signaling {

// ========== 辅助函数实现 ==========

std::string GTFTEID::to_string() const {
    std::ostringstream oss;
    oss << "F-TEID [TEID: 0x" << std::hex << teid << std::dec
        << ", Interface: " << static_cast<int>(interface_type);

    if (ipv4_present) {
        oss << ", IPv4: " << ((ipv4_address >> 24) & 0xFF)
            << "." << ((ipv4_address >> 16) & 0xFF)
            << "." << ((ipv4_address >> 8) & 0xFF)
            << "." << (ipv4_address & 0xFF);
    }

    if (ipv6_present) {
        oss << ", IPv6: present";
    }

    oss << "]";
    return oss.str();
}

std::string EPSBearerQoS::to_string() const {
    std::ostringstream oss;
    oss << "QoS [QCI: " << static_cast<int>(qci)
        << ", MBR-DL: " << (mbr_dl / 1000) << " kbps"
        << ", MBR-UL: " << (mbr_ul / 1000) << " kbps";

    if (gbr_dl > 0 || gbr_ul > 0) {
        oss << ", GBR-DL: " << (gbr_dl / 1000) << " kbps"
            << ", GBR-UL: " << (gbr_ul / 1000) << " kbps";
    }

    oss << "]";
    return oss.str();
}

std::string BearerContext::to_string() const {
    std::ostringstream oss;
    oss << "Bearer [EBI: " << static_cast<int>(ebi) << ", QoS: " << qos.to_string() << "]";
    return oss.str();
}

std::string GTPv2Header::to_string() const {
    std::ostringstream oss;
    oss << "GTPv2 Header [Type: " << static_cast<int>(message_type)
        << " (" << GTPv2Parser::get_message_type_name(message_type) << ")"
        << ", TEID: 0x" << std::hex << teid << std::dec
        << ", Seq: " << sequence_number
        << ", Length: " << message_length << "]";
    return oss.str();
}

std::string GTPv2IE::to_string() const {
    std::ostringstream oss;
    oss << "IE [Type: " << type
        << " (" << GTPv2Parser::get_ie_type_name(type) << ")"
        << ", Instance: " << static_cast<int>(instance)
        << ", Length: " << length << "]";
    return oss.str();
}

std::string GTPv2Info::get_message_name() const {
    return GTPv2Parser::get_message_type_name(header.message_type);
}

std::string GTPv2Info::to_string() const {
    std::ostringstream oss;
    oss << "GTPv2 " << (is_request ? "Request" : (is_response ? "Response" : "Indication"))
        << " - " << get_message_name() << "\n"
        << header.to_string() << "\n"
        << "IEs: " << ies.size() << " elements\n";

    if (imsi.has_value()) {
        oss << "IMSI: present\n";
    }
    if (cause.has_value()) {
        oss << "Cause: " << static_cast<int>(cause.value()) << " ("
            << GTPv2Parser::get_cause_name(cause.value()) << ")\n";
    }
    if (apn.has_value()) {
        oss << "APN: " << apn.value() << "\n";
    }
    if (sender_fteid.has_value()) {
        oss << "Sender F-TEID: " << sender_fteid.value().to_string() << "\n";
    }
    if (receiver_fteid.has_value()) {
        oss << "Receiver F-TEID: " << receiver_fteid.value().to_string() << "\n";
    }
    if (!bearer_contexts.empty()) {
        oss << "Bearers: " << bearer_contexts.size() << "\n";
    }

    return oss.str();
}

// ========== GTPv2Parser 实现 ==========

const ProtocolInfo& GTPv2Parser::get_protocol_info() const noexcept {
    static ProtocolInfo info = {
        "GTPv2-C",
        0x302,  // GTPv2协议类型
        8,       // 最小头部大小
        12,      // 最小消息大小
        1500     // 最大消息大小
    };
    return info;
}

bool GTPv2Parser::can_parse(const BufferView& buffer) const noexcept {
    if (buffer.size() < 8) return false;

    // GTPv2前3位应为010（版本2）
    uint8_t version = (buffer[0] >> 5) & 0x07;
    if (version != 2) return false;

    // 检查协议类型（GTP=0x30-0x3F）
    // 通常在UDP上层，需要检查端口2123
    return true;
}

ParseResult GTPv2Parser::parse(ParseContext& context) noexcept {
    reset();
    const auto& buffer = context.buffer;

    if (!can_parse(buffer)) {
        return ParseResult::InvalidFormat;
    }

    if (!parse_gtpv2_message(buffer, current_info_)) {
        return ParseResult::InvalidFormat;
    }

    // 存储解析结果到context
    context.metadata["gtpv2_info"] = current_info_;

    return ParseResult::Success;
}

void GTPv2Parser::reset() noexcept {
    current_info_ = GTPv2Info{};
    parse_success_ = false;
}

bool GTPv2Parser::parse_gtpv2_message(const BufferView& buffer, GTPv2Info& info) {
    if (buffer.size() < 8) return false;

    // 解析头部
    if (!parse_header(buffer, info.header)) {
        return false;
    }

    // 检查消息完整性
    size_t total_length = 4 + info.header.message_length;
    if (buffer.size() < total_length) {
        return false;
    }

    // 解析IEs
    size_t offset = 8; // 基本头部大小
    if (info.header.teid_present) {
        offset = 12; // 包含TEID的头部
    }

    BufferView ies_buffer = buffer.substr(offset);
    if (!parse_ies(ies_buffer, info.ies)) {
        return false;
    }

    // 提取关键字段
    info.is_request = is_request_message(info.header.message_type);
    info.is_response = is_response_message(info.header.message_type);
    info.is_error = is_error_indication(info.header.message_type);
    info.parse_timestamp = std::chrono::steady_clock::now();

    // 解析重要的IE
    for (const auto& ie : info.ies) {
        switch (static_cast<GTPv2IEType>(ie.type)) {
            case GTPv2IEType::IMSI:
                extract_imsi(ie, info.imsi.emplace());
                break;
            case GTPv2IEType::Cause:
                info.cause = static_cast<GTPv2Cause>(ie.value[0]);
                break;
            case GTPv2IEType::APN:
                extract_apn(ie, info.apn.emplace());
                break;
            case GTPv2IEType::FTEID:
                if (!info.sender_fteid.has_value() && ie.instance == 0) {
                    extract_fteid(ie, info.sender_fteid.emplace());
                } else {
                    extract_fteid(ie, info.receiver_fteid.emplace());
                }
                break;
            case GTPv2IEType::ChargingID:
                extract_charging_id(ie, info.charging_id.emplace());
                break;
            case GTPv2IEType::BearerContext: {
                BearerContext ctx;
                if (parse_bearer_context(BufferView(ie.value.data(), ie.value.size()), ctx)) {
                    info.bearer_contexts.push_back(ctx);
                }
                break;
            }
            default:
                break;
        }
    }

    return true;
}

GTPv2Info GTPv2Parser::parse_gtpv2_header(const BufferView& buffer) {
    GTPv2Info info;
    parse_gtpv2_message(buffer, info);
    return info;
}

bool GTPv2Parser::parse_header(const BufferView& buffer, GTPv2Header& header) {
    if (buffer.size() < 8) return false;

    // 第1字节: version(3b) + piggybacking(1b) + teid_present(1b) + spare(3b)
    header.version = (buffer[0] >> 5) & 0x07;
    header.piggybacking = (buffer[0] & 0x10) != 0;
    header.teid_present = (buffer[0] & 0x08) != 0;

    // 第2字节: 消息类型
    header.message_type = buffer[1];

    // 第3-4字节: 消息长度
    header.message_length = (buffer[2] << 8) | buffer[3];

    // 第5-8字节: TEID (如果存在)
    if (header.teid_present && buffer.size() >= 12) {
        header.teid = (buffer[4] << 24) | (buffer[5] << 16) |
                      (buffer[6] << 8) | buffer[7];

        // 第9-10字节: 序列号
        header.sequence_number = (buffer[8] << 8) | buffer[9];

        // 第11字节: spare
        header.spare = buffer[10];
    } else if (buffer.size() >= 8) {
        // 没有TEID
        header.sequence_number = (buffer[4] << 8) | buffer[5];
        header.spare = buffer[6];
    }

    return true;
}

bool GTPv2Parser::parse_ies(const BufferView& buffer, std::vector<GTPv2IE>& ies) {
    size_t offset = 0;
    while (offset + 4 <= buffer.size()) {
        GTPv2IE ie;

        // IE类型 (2字节)
        ie.type = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;

        // IE长度 (2字节)
        ie.length = (buffer[offset] << 8) | buffer[offset + 1];
        offset += 2;

        // Instance和Spare (第4字节的高4位)
        ie.instance = (buffer[offset] >> 4) & 0x0F;

        // IE值
        size_t ie_value_len = ie.length;
        if (offset + 1 + ie_value_len <= buffer.size()) {
            ie.value.assign(buffer.data() + offset + 1,
                          buffer.data() + offset + 1 + ie_value_len);
            offset += 1 + ie_value_len;

            // 填充到4字节边界
            size_t padding = (4 - ((2 + 2 + 1 + ie_value_len) % 4)) % 4;
            offset += padding;

            ies.push_back(ie);
        } else {
            break;
        }
    }

    return true;
}

bool GTPv2Parser::parse_ie(const BufferView& buffer, GTPv2IE& ie) {
    if (buffer.size() < 4) return false;

    ie.type = (buffer[0] << 8) | buffer[1];
    ie.length = (buffer[2] << 8) | buffer[3];
    ie.instance = (buffer[4] >> 4) & 0x0F;

    if (buffer.size() >= 5 + ie.length) {
        ie.value.assign(buffer.data() + 5, buffer.data() + 5 + ie.length);
        return true;
    }

    return false;
}

bool GTPv2Parser::parse_fteid(const BufferView& buffer, GTFTEID& fteid) {
    if (buffer.size() < 9) return false;

    // 第1字节: 标志位
    uint8_t flags = buffer[0];
    fteid.ipv4_present = (flags & 0x80) != 0;
    fteid.ipv6_present = (flags & 0x40) != 0;
    fteid.interface_type = buffer[1];

    // TEID (4字节)
    fteid.teid = (buffer[4] << 24) | (buffer[5] << 16) |
                 (buffer[6] << 8) | buffer[7];

    size_t offset = 8;

    // IPv4地址 (4字节)
    if (fteid.ipv4_present && offset + 4 <= buffer.size()) {
        fteid.ipv4_address = (buffer[offset] << 24) | (buffer[offset + 1] << 16) |
                              (buffer[offset + 2] << 8) | buffer[offset + 3];
        offset += 4;
    }

    // IPv6地址 (16字节)
    if (fteid.ipv6_present && offset + 16 <= buffer.size()) {
        std::copy(buffer.data() + offset, buffer.data() + offset + 16, fteid.ipv6_address);
    }

    return true;
}

bool GTPv2Parser::parse_bearer_qos(const BufferView& buffer, EPSBearerQoS& qos) {
    if (buffer.size() < 22) return false;

    // 第1字节: QCI
    qos.qci = buffer[0];

    // 第2-5字节: MBR Uplink (bits)
    uint64_t mbr_ul = (buffer[1] << 24) | (buffer[2] << 16) |
                      (buffer[3] << 8) | buffer[4];
    qos.mbr_ul = mbr_ul * 1000; // 转换为bps

    // 第6-9字节: MBR Downlink
    uint64_t mbr_dl = (buffer[5] << 24) | (buffer[6] << 16) |
                      (buffer[7] << 8) | buffer[8];
    qos.mbr_dl = mbr_dl * 1000;

    // 第10-13字节: GBR Uplink
    uint64_t gbr_ul = (buffer[9] << 24) | (buffer[10] << 16) |
                      (buffer[11] << 8) | buffer[12];
    qos.gbr_ul = gbr_ul * 1000;

    // 第14-17字节: GBR Downlink
    uint64_t gbr_dl = (buffer[13] << 24) | (buffer[14] << 16) |
                      (buffer[15] << 8) | buffer[16];
    qos.gbr_dl = gbr_dl * 1000;

    return true;
}

bool GTPv2Parser::parse_bearer_context(const BufferView& buffer, BearerContext& ctx) {
    // 简化实现 - 实际需要递归解析IE组
    size_t offset = 0;
    while (offset + 4 <= buffer.size()) {
        uint16_t ie_type = (buffer[offset] << 8) | buffer[offset + 1];
        uint16_t ie_len = (buffer[offset + 2] << 8) | buffer[offset + 3];
        uint8_t ie_instance = (buffer[offset + 4] >> 4) & 0x0F;

        if (ie_type == static_cast<uint16_t>(GTPv2IEType::EBI)) {
            if (offset + 5 <= buffer.size()) {
                ctx.ebi = buffer[offset + 5];
            }
        }

        offset += 4 + ie_len;
        if (offset % 4 != 0) {
            offset += 4 - (offset % 4);
        }
    }

    return true;
}

bool GTPv2Parser::extract_imsi(const GTPv2IE& ie, std::vector<uint8_t>& imsi) {
    imsi = ie.value;
    return !imsi.empty();
}

bool GTPv2Parser::extract_cause(const GTPv2IE& ie, GTPv2Cause& cause) {
    if (ie.value.empty()) return false;
    cause = static_cast<GTPv2Cause>(ie.value[0]);
    return true;
}

bool GTPv2Parser::extract_apn(const GTPv2IE& ie, std::string& apn) {
    if (ie.value.empty()) return false;

    // APN使用标签格式，需要转换
    std::string result;
    size_t offset = 0;
    while (offset < ie.value.size()) {
        uint8_t len = ie.value[offset];
        if (len == 0) break;

        if (offset + 1 + len <= ie.value.size()) {
            if (!result.empty()) result += ".";
            result.append(reinterpret_cast<const char*>(ie.value.data() + offset + 1), len);
            offset += 1 + len;
        } else {
            break;
        }
    }

    apn = result;
    return true;
}

bool GTPv2Parser::extract_fteid(const GTPv2IE& ie, GTFTEID& fteid) {
    return parse_fteid(BufferView(ie.value.data(), ie.value.size()), fteid);
}

bool GTPv2Parser::extract_charging_id(const GTPv2IE& ie, uint32_t& charging_id) {
    if (ie.value.size() < 4) return false;

    charging_id = (ie.value[0] << 24) | (ie.value[1] << 16) |
                  (ie.value[2] << 8) | ie.value[3];
    return true;
}

bool GTPv2Parser::is_request_message(uint8_t type) const {
    // GTPv2请求消息通常是奇数类型
    return (type % 2) != 0;
}

bool GTPv2Parser::is_response_message(uint8_t type) const {
    // GTPv2响应消息通常是偶数类型
    return (type % 2) == 0 && type != 0;
}

bool GTPv2Parser::is_error_indication(uint8_t type) const {
    return type == static_cast<uint8_t>(GTPv2MessageType::ErrorIndication);
}

std::string GTPv2Parser::get_message_type_name(uint8_t type) {
    switch (static_cast<GTPv2MessageType>(type)) {
        case GTPv2MessageType::EchoRequest: return "Echo Request";
        case GTPv2MessageType::EchoResponse: return "Echo Response";
        case GTPv2MessageType::CreateSessionRequest: return "Create Session Request";
        case GTPv2MessageType::CreateSessionResponse: return "Create Session Response";
        case GTPv2MessageType::ModifyBearerRequest: return "Modify Bearer Request";
        case GTPv2MessageType::ModifyBearerResponse: return "Modify Bearer Response";
        case GTPv2MessageType::DeleteSessionRequest: return "Delete Session Request";
        case GTPv2MessageType::DeleteSessionResponse: return "Delete Session Response";
        case GTPv2MessageType::CreateBearerRequest: return "Create Bearer Request";
        case GTPv2MessageType::CreateBearerResponse: return "Create Bearer Response";
        case GTPv2MessageType::UpdateBearerRequest: return "Update Bearer Request";
        case GTPv2MessageType::UpdateBearerResponse: return "Update Bearer Response";
        case GTPv2MessageType::DeleteBearerRequest: return "Delete Bearer Request";
        case GTPv2MessageType::DeleteBearerResponse: return "Delete Bearer Response";
        case GTPv2MessageType::DownlinkDataNotification: return "Downlink Data Notification";
        case GTPv2MessageType::DownlinkDataNotificationAck: return "Downlink Data Notification Ack";
        case GTPv2MessageType::ErrorIndication: return "Error Indication";
        default: return "Unknown (0x" + std::to_string(type) + ")";
    }
}

std::string GTPv2Parser::get_cause_name(GTPv2Cause cause) {
    switch (cause) {
        case GTPv2Cause::RequestAccepted: return "Request Accepted";
        case GTPv2Cause::RequestAcceptedPartial: return "Request Accepted Partial";
        case GTPv2Cause::LocalDetached: return "Local Detached";
        case GTPv2Cause::CompleteDetached: return "Complete Detached";
        case GTPv2Cause::RATChangedFrom3GPPToNon3GPP: return "RAT Changed From 3GPP To Non-3GPP";
        case GTPv2Cause::ResourcesUnavailable: return "Resources Unavailable";
        case GTPv2Cause::UnknownAPN: return "Unknown APN";
        case GTPv2Cause::InvalidMandatoryInformation: return "Invalid Mandatory Information";
        default: return "Unknown";
    }
}

std::string GTPv2Parser::get_ie_type_name(uint16_t ie_type) {
    switch (static_cast<GTPv2IEType>(ie_type)) {
        case GTPv2IEType::IMSI: return "IMSI";
        case GTPv2IEType::Cause: return "Cause";
        case GTPv2IEType::Recovery: return "Recovery";
        case GTPv2IEType::APN: return "APN";
        case GTPv2IEType::AMBR: return "AMBR";
        case GTPv2IEType::EBI: return "EBI";
        case GTPv2IEType::IPv4: return "IPv4";
        case GTPv2IEType::IPv6: return "IPv6";
        case GTPv2IEType::FTEID: return "F-TEID";
        case GTPv2IEType::BearerContext: return "Bearer Context";
        case GTPv2IEType::ChargingID: return "Charging ID";
        case GTPv2IEType::PDNType: return "PDN Type";
        default: return "Unknown";
    }
}

} // namespace protocol_parser::signaling
