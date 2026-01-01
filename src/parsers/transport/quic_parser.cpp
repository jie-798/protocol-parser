#include "parsers/transport/quic_parser.hpp"

namespace protocol_parser::parsers {

// ============================================================================
// QuicParser 实现
// ============================================================================

QuicParser::QuicParser() {
    protocol_info_ = ProtocolInfo{
        .name = "QUIC",
        .type = 0xFF,  // 伪协议类型（基于 UDP）
        .header_size = 0,  // 可变长度
        .min_packet_size = 20,  // 最小长包头
        .max_packet_size = 1500  // 标准 MTU
    };

    reset();
}

const ProtocolInfo& QuicParser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool QuicParser::is_quic_packet(const BufferView& buffer) noexcept {
    // QUIC 包的第一个字节决定包头类型
    if (buffer.size() < 1) {
        return false;
    }

    uint8_t first_byte = buffer[0];

    // 检查包头格式位（Header Form, bit 7）
    // 1 = 长包头
    // 0 = 短包头

    // 长包头检查
    if (first_byte & 0x80) {
        // 长包头需要至少 5 个字节
        if (buffer.size() < 5) {
            return false;
        }

        // 检查版本号（不能是 0，0 是版本协商包）
        uint32_t version = buffer.read_be32(1);
        if (version == 0) {
            // 版本协商包
            return true;
        }

        // QUIC 版本应该是已知的版本之一
        // v1: 0x00000001
        // v2: 0x709a50c4 (draft)
        return (version == 0x00000001 || version == 0x709a50c4);
    } else {
        // 短包头：需要检查连接 ID
        // 短包头格式: 0XXXXXXX [Connection ID] [Packet Number] [Payload]
        if (buffer.size() < 1 + 8) {  // 最小：1 字节头 + 8 字节连接 ID
            return false;
        }

        // 短包头比较难识别，通常需要通过连接状态
        // 这里简单假设：如果是 UDP 且看起来像短包头，可能是 QUIC
        return true;
    }
}

bool QuicParser::can_parse(const BufferView& buffer) const noexcept {
    return is_quic_packet(buffer);
}

ParseResult QuicParser::parse(ParseContext& context) noexcept {
    const BufferView& buffer = context.buffer;

    if (buffer.size() < protocol_info_.min_packet_size) {
        return ParseResult::BufferTooSmall;
    }

    size_t offset = 0;
    uint8_t first_byte = buffer[offset++];

    // 检查包头格式位
    bool is_long_header = (first_byte & 0x80) != 0;

    result_ = QuicParseResult{};
    result_.is_long_header = is_long_header;

    if (is_long_header) {
        if (!parse_long_header(buffer, offset)) {
            return ParseResult::InvalidFormat;
        }
    } else {
        if (!parse_short_header(buffer, offset)) {
            return ParseResult::InvalidFormat;
        }
    }

    // 保存结果到上下文
    context.metadata["quic_result"] = result_;

    return ParseResult::Success;
}

bool QuicParser::parse_long_header(const BufferView& buffer, size_t& offset) {
    // 长包头格式（RFC 9000 Section 17.2）:
    // +====+=========+================================+
    // | 1  | Version | ... (其余字段)                |
    // +====+=========+================================+
    //
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+
    // |1|1|1|1|Version|
    // +-+-+-+-+-+-+-+-+
    // |        Destination Connection ID Length (8)  |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |               Destination Connection ID (0..160)      ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                    Source Connection ID Length (8)   |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                  Source Connection ID (0..160)       ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    // 提取版本号
    if (offset + 4 > buffer.size()) {
        return false;
    }

    result_.long_header.header_form = 1;
    result_.long_header.version = buffer.read_be32(offset);
    offset += 4;

    // 检查版本协商包
    if (result_.long_header.version == 0) {
        result_.long_header.packet_type = QuicPacketType::VersionNegotiation;
        return true;  // 版本协商包特殊处理
    }

    // 提取包类型
    uint8_t first_byte = buffer[0];
    uint8_t type_bits = (first_byte >> 4) & 0x03;  // bits 5-4

    switch (type_bits) {
        case 0x00:
            result_.long_header.packet_type = QuicPacketType::Initial;
            break;
        case 0x01:
            result_.long_header.packet_type = QuicPacketType::ZeroRTTProtected;
            break;
        case 0x02:
            result_.long_header.packet_type = QuicPacketType::Handshake;
            break;
        case 0x03:
            result_.long_header.packet_type = QuicPacketType::Retry;
            break;
    }

    // 解析目的连接 ID
    if (offset + 1 > buffer.size()) return false;
    result_.long_header.destination_id_length = buffer[offset++];

    if (!parse_connection_id(buffer, offset, result_.long_header.destination_id)) {
        return false;
    }

    // 解析源连接 ID
    if (offset + 1 > buffer.size()) return false;
    result_.long_header.source_id_length = buffer[offset++];

    if (!parse_connection_id(buffer, offset, result_.long_header.source_id)) {
        return false;
    }

    // 解析包号（部分包类型有）
    if (result_.long_header.packet_type == QuicPacketType::Initial ||
        result_.long_header.packet_type == QuicPacketType::Handshake) {
        auto packet_number = parse_packet_number(buffer, offset);
        if (packet_number) {
            result_.long_header.packet_number = *packet_number;
        }
    }

    // 剩余的是载荷（帧）
    if (offset < buffer.size()) {
        size_t payload_size = buffer.size() - offset;
        result_.payload.assign(buffer.data() + offset, buffer.data() + buffer.size());

        // 尝试解析帧
        parse_frames(buffer, offset);
    }

    return true;
}

bool QuicParser::parse_short_header(const BufferView& buffer, size_t& offset) {
    // 短包头格式（RFC 9000 Section 17.3）:
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+
    // |0|1|2|3|Packet Number Length (2)  |
    // +-+-+-+-+-+-+-+-+
    // |               Destination Connection ID (0/8/16/32...) ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                      Packet Number (8/16/24/32)      ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                     Protected Payload (*)           ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    result_.short_header.header_form = 0;

    // 解析连接 ID（简化：假设 8 字节）
    // 实际应该根据连接配置确定长度
    size_t conn_id_len = 8;  // 默认 8 字节

    if (offset + conn_id_len > buffer.size()) {
        return false;
    }

    result_.short_header.connection_id.assign(
        buffer.data() + offset,
        buffer.data() + offset + conn_id_len
    );
    offset += conn_id_len;

    // 解析包号（简化：假设 4 字节）
    uint8_t pn_length = (buffer[0] & 0x03) + 1;  // bits 0-1

    if (offset + pn_length > buffer.size()) {
        return false;
    }

    uint64_t packet_number = 0;
    for (size_t i = 0; i < pn_length; ++i) {
        packet_number = (packet_number << 8) | buffer[offset++];
    }
    result_.short_header.packet_number = packet_number;

    // 剩余的是载荷
    if (offset < buffer.size()) {
        result_.payload.assign(buffer.data() + offset, buffer.data() + buffer.size());
    }

    return true;
}

bool QuicParser::parse_connection_id(const BufferView& buffer,
                                    size_t& offset,
                                    std::vector<uint8_t>& conn_id) {
    if (offset > buffer.size()) {
        return false;
    }

    size_t id_len = buffer[offset - 1];  // 长度在前一个字节

    if (offset + id_len > buffer.size()) {
        return false;
    }

    conn_id.assign(buffer.data() + offset, buffer.data() + offset + id_len);
    offset += id_len;

    return true;
}

std::optional<uint64_t> QuicParser::parse_packet_number(
    const BufferView& buffer,
    size_t& offset) {

    if (offset >= buffer.size()) {
        return std::nullopt;
    }

    // 包号长度由第一个字节的低 2 位决定
    // 00 = 1 字节
    // 01 = 2 字节
    // 10 = 4 字节
    // 11 = 8 字节（不常见）

    uint8_t first_byte = buffer[0];
    uint8_t pn_length = (first_byte & 0x03);

    size_t bytes_to_read = 0;
    switch (pn_length) {
        case 0x00: bytes_to_read = 1; break;
        case 0x01: bytes_to_read = 2; break;
        case 0x02: bytes_to_read = 4; break;
        case 0x03: bytes_to_read = 8; break;
    }

    if (offset + bytes_to_read > buffer.size()) {
        return std::nullopt;
    }

    uint64_t packet_number = 0;
    for (size_t i = 0; i < bytes_to_read; ++i) {
        packet_number = (packet_number << 8) | buffer[offset++];
    }

    return packet_number;
}

std::optional<uint64_t> QuicParser::parse_varint(
    const BufferView& buffer,
    size_t& offset) {

    // QUIC 可变长度整数编码（RFC 9000 Section 16）:
    // +=======+========+=============+===================+
    // | 2 MSB | Length | Usable Bits | Format            |
    // +=======+========+=============+===================+
    // | 00    | 1      | 6           | 0XXXXXXX          |
    // | 01    | 2      | 14          | 01XXXXXX XXXXXXXX |
    // | 10    | 4      | 30          | 10XXXXXX ...*     |
    // | 11    | 8      | 62          | 11XXXXXX ...*     |
    // +-------+--------+-------------+-------------------+

    if (offset >= buffer.size()) {
        return std::nullopt;
    }

    uint8_t first_byte = buffer[offset];
    uint8_t two_msb = (first_byte >> 6) & 0x03;

    uint64_t value = 0;
    size_t bytes_to_read = 0;

    switch (two_msb) {
        case 0x00:
            // 1 字节
            value = first_byte & 0x3F;
            offset += 1;
            return value;

        case 0x01:
            // 2 字节
            bytes_to_read = 2;
            break;
        case 0x02:
            // 4 字节
            bytes_to_read = 4;
            break;
        case 0x03:
            // 8 字节
            bytes_to_read = 8;
            break;
    }

    if (offset + bytes_to_read > buffer.size()) {
        return std::nullopt;
    }

    // 跳过第一个字节
    offset++;

    // 读取剩余字节
    for (size_t i = 0; i < bytes_to_read - 1; ++i) {
        value = (value << 8) | buffer[offset++];
    }

    // 合并第一个字节的低 6 位
    value = (value << 6) | (first_byte & 0x3F);

    return value;
}

bool QuicParser::parse_frames(const BufferView& buffer, size_t offset) {
    // 解析所有帧（简化实现）
    while (offset < buffer.size()) {
        auto frame_type = parse_varint(buffer, offset);
        if (!frame_type) {
            break;
        }

        QuicParseResult::Frame frame;
        frame.type = static_cast<QuicFrameType>(*frame_type);

        // 简化：不解析每种帧的具体内容
        // 实际应用中需要根据帧类型解析
        result_.frames.push_back(frame);
    }

    return true;
}

void QuicParser::reset() noexcept {
    result_ = QuicParseResult{};
    state_ = ParserState::Initial;
    current_offset_ = 0;
}

} // namespace protocol_parser::parsers
