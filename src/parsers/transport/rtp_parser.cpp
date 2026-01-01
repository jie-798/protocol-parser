#include "parsers/transport/rtp_parser.hpp"

namespace protocol_parser::parsers {

// ============================================================================
// RtpParseResult 辅助函数
// ============================================================================

const char* RtpParseResult::get_payload_type_name() const {
    switch (static_cast<PayloadType>(payload_type)) {
        case PayloadType::PCMU: return "G.711 μ-law";
        case PayloadType::GSM: return "GSM";
        case PayloadType::G723: return "G.723";
        case PayloadType::PCMA: return "G.711 A-law";
        case PayloadType::G722: return "G.722";
        case PayloadType::G729: return "G.729";
        case PayloadType::MP2T: return "MPEG-2 TS";
        case PayloadType::H263: return "H.263";
        case PayloadType::Dynamic:
        default:
            if (payload_type >= 96 && payload_type <= 127) {
                return "Dynamic";
            }
            return "Unknown";
    }
}

// ============================================================================
// RtpParser 实现
// ============================================================================

RtpParser::RtpParser() {
    protocol_info_ = ProtocolInfo{
        .name = "RTP",
        .type = 0xFF,  // 运行在 UDP 之上
        .header_size = 12,  // 最小 RTP 头部
        .min_packet_size = 12,
        .max_packet_size = 1500
    };

    reset();
}

const ProtocolInfo& RtpParser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool RtpParser::is_rtp_packet(const BufferView& buffer) noexcept {
    // RTP 头部格式（RFC 3550 Section 5.1）:
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |V=2|P|X|  CC   |M|     PT      |       sequence number  |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                           timestamp                       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |           synchronization source (SSRC) identifier       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    if (buffer.size() < 12) {
        return false;
    }

    uint8_t first_byte = buffer[0];

    // 检查版本号（应该是 2）
    uint8_t version = (first_byte >> 6) & 0x03;
    if (version != 2) {
        return false;
    }

    // 检查载荷类型（有效范围 0-127，96-127 是动态类型）
    uint8_t payload_type = buffer[1] & 0x7F;
    if (payload_type > 127) {
        return false;
    }

    // RTCP 检查（RTP 和 RTCP 使用相邻端口）
    // RTCP 包类型范围 200-207
    if (payload_type >= 200 && payload_type <= 207) {
        return false;  // 这是 RTCP
    }

    return true;
}

bool RtpParser::is_rtcp_packet(const BufferView& buffer) noexcept {
    if (buffer.size() < 4) {
        return false;
    }

    uint8_t first_byte = buffer[0];

    // 检查版本号（应该是 2）
    uint8_t version = (first_byte >> 6) & 0x03;
    if (version != 2) {
        return false;
    }

    // 检查包类型（RTCP 包类型 200-207）
    uint8_t packet_type = buffer[1];
    if (packet_type >= 200 && packet_type <= 207) {
        return true;
    }

    return false;
}

bool RtpParser::can_parse(const BufferView& buffer) const noexcept {
    return is_rtp_packet(buffer) || is_rtcp_packet(buffer);
}

ParseResult RtpParser::parse(ParseContext& context) noexcept {
    const BufferView& buffer = context.buffer;

    if (buffer.size() < protocol_info_.min_packet_size) {
        return ParseResult::BufferTooSmall;
    }

    reset();

    // 判断是 RTP 还是 RTCP
    if (is_rtcp_packet(buffer)) {
        is_rtcp_ = true;
        if (!parse_rtcp_packet(buffer)) {
            return ParseResult::InvalidFormat;
        }
        context.metadata["rtcp_result"] = rtcp_result_;
    } else {
        is_rtcp_ = false;
        size_t offset = 0;
        if (!parse_rtp_header(buffer, offset)) {
            return ParseResult::InvalidFormat;
        }

        // 读取载荷
        if (offset < buffer.size()) {
            size_t payload_size = buffer.size() - offset;
            rtp_result_.payload.assign(buffer.data() + offset,
                                      buffer.data() + buffer.size());
        }

        context.metadata["rtp_result"] = rtp_result_;
    }

    return ParseResult::Success;
}

bool RtpParser::parse_rtp_header(const BufferView& buffer, size_t& offset) {
    if (buffer.size() < 12) {
        return false;
    }

    // 解析第一个字节
    uint8_t byte0 = buffer[offset++];
    rtp_result_.version = (byte0 >> 6) & 0x03;
    rtp_result_.padding = (byte0 >> 5) & 0x01;
    rtp_result_.extension = (byte0 >> 4) & 0x01;
    rtp_result_.csrc_count = byte0 & 0x0F;

    // 解析第二个字节
    uint8_t byte1 = buffer[offset++];
    rtp_result_.marker = (byte1 >> 7) & 0x01;
    rtp_result_.payload_type = byte1 & 0x7F;

    // 解析序列号
    rtp_result_.sequence_number = buffer.read_be16(offset);
    offset += 2;

    // 解析时间戳
    rtp_result_.timestamp = buffer.read_be32(offset);
    offset += 4;

    // 解析 SSRC
    rtp_result_.ssrc = buffer.read_be32(offset);
    offset += 4;

    // 解析 CSRC 列表（如果有）
    if (rtp_result_.csrc_count > 0) {
        if (!parse_csrc_list(buffer, offset, rtp_result_.csrc_count)) {
            return false;
        }
    }

    // 解析扩展头部（如果有）
    if (rtp_result_.extension) {
        if (!parse_extension_header(buffer, offset)) {
            return false;
        }
    }

    return true;
}

bool RtpParser::parse_csrc_list(const BufferView& buffer,
                               size_t& offset,
                               uint8_t csrc_count) {
    if (offset + csrc_count * 4 > buffer.size()) {
        return false;
    }

    rtp_result_.csrc_list.reserve(csrc_count);

    for (uint8_t i = 0; i < csrc_count; ++i) {
        uint32_t csrc = buffer.read_be32(offset);
        rtp_result_.csrc_list.push_back(csrc);
        offset += 4;
    }

    return true;
}

bool RtpParser::parse_extension_header(const BufferView& buffer, size_t& offset) {
    // 扩展头部格式（RFC 5285）:
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |       defined by profile       |           length          |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                        header extension                   |
    // |                             ....                          |

    if (offset + 4 > buffer.size()) {
        return false;
    }

    RtpParseResult::ExtensionHeader ext_header;

    ext_header.profile = buffer.read_be16(offset);
    offset += 2;

    uint16_t length = buffer.read_be16(offset);
    offset += 2;

    // 读取扩展数据（length 是以 32 位字为单位）
    if (offset + (length + 1) * 4 > buffer.size()) {
        return false;
    }

    for (uint16_t i = 0; i <= length; ++i) {
        uint32_t data = buffer.read_be32(offset);
        ext_header.extension_data.push_back(data);
        offset += 4;
    }

    rtp_result_.extension_header = ext_header;

    return true;
}

bool RtpParser::parse_rtcp_packet(const BufferView& buffer) {
    if (buffer.size() < 4) {
        return false;
    }

    // RTCP 头部格式:
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |V=2|P|    RC   |      PT       |            length       |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    uint8_t byte0 = buffer[0];
    rtcp_result_.version = (byte0 >> 6) & 0x03;
    // 跳过 reception report count
    rtcp_result_.packet_type = static_cast<RtcpPacketType>(buffer[1]);
    rtcp_result_.length = (buffer.read_be16(2) + 1) * 4;  // 转换为字节数

    // 验证长度
    if (buffer.size() < rtcp_result_.length) {
        return false;
    }

    // 复制数据
    rtcp_result_.data.assign(buffer.data(), buffer.data() + rtcp_result_.length);

    return true;
}

void RtpParser::reset() noexcept {
    rtp_result_ = RtpParseResult{};
    rtp_result_.version = 2;
    rtcp_result_ = RtcpParseResult{};
    state_ = ParserState::Initial;
    is_rtcp_ = false;
}

} // namespace protocol_parser::parsers
