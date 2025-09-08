#include "../../../include/parsers/transport/udp_parser.hpp"
#include <cstring>

namespace protocol_parser::parsers {

// UDP协议信息
const ProtocolInfo UDPParser::protocol_info_ = {
    "UDP",
    17,     // IP协议号
    8,      // 头长度
    8,      // 最小包大小
    65535   // 最大包大小
};

UDPParser::UDPParser() : BaseParser() {
    reset();
}

const ProtocolInfo& UDPParser::get_protocol_info() const noexcept {
    return protocol_info_;
}

bool UDPParser::can_parse(const core::BufferView& buffer) const noexcept {
    return buffer.size() >= UDPHeader::SIZE;
}

ParseResult UDPParser::parse(ParseContext& context) noexcept {
    reset();
    
    // 解析UDP头部
    auto header_result = parse_header(context);
    if (header_result != ParseResult::Success) {
        return header_result;
    }
    
    // 解析载荷
    auto payload_result = parse_payload(context);
    if (payload_result != ParseResult::Success) {
        return payload_result;
    }
    
    // 将解析结果存储到metadata中
    context.metadata["udp_result"] = result_;
    
    context.state = ParserState::Complete;
    return ParseResult::Success;
}

void UDPParser::reset() noexcept {
    result_ = UDPParseResult{};
}

double UDPParser::get_progress() const noexcept {
    return 1.0; // 简单实现，总是返回100%
}

ParseResult UDPParser::parse_header(ParseContext& context) noexcept {
    if (context.buffer.size() < UDPHeader::SIZE) {
        return ParseResult::NeedMoreData;
    }
    
    const uint8_t* data = context.buffer.data();
    
    // 解析UDP头部字段
    result_.header.src_port = (data[0] << 8) | data[1];
    result_.header.dst_port = (data[2] << 8) | data[3];
    result_.header.length = (data[4] << 8) | data[5];
    result_.header.checksum = (data[6] << 8) | data[7];
    
    // 验证长度字段
    if (result_.header.length < UDPHeader::SIZE) {
        return ParseResult::InvalidFormat;
    }
    
    if (context.buffer.size() < result_.header.length) {
        return ParseResult::NeedMoreData;
    }
    
    context.offset = UDPHeader::SIZE;
    return ParseResult::Success;
}

ParseResult UDPParser::parse_payload(ParseContext& context) noexcept {
    size_t payload_length = result_.header.length - UDPHeader::SIZE;
    
    if (payload_length > 0) {
        result_.payload = core::BufferView(
            context.buffer.data() + UDPHeader::SIZE,
            payload_length
        );
        result_.payload_length = payload_length;
    } else {
        result_.payload = core::BufferView(nullptr, 0);
        result_.payload_length = 0;
    }
    
    // 简单的校验和验证（这里只是标记为有效）
    result_.checksum_valid = true;
    
    return ParseResult::Success;
}

// 注册UDP解析器
REGISTER_PARSER(17, UDPParserFactory);

} // namespace protocol_parser::parsers